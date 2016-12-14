/*
 * Copyright © 2016 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Lyude Paul <lyude@redhat.com>
 */

#include "config.h"
#include "igt.h"

#include <fcntl.h>
#include <string.h>

typedef struct {
	int drm_fd;
	struct chamelium *chamelium;
	const struct chamelium_port *ports;
	int port_count;
} data_t;

#define HOTPLUG_TIMEOUT 20 /* seconds */

static void
require_connector_present(data_t *data, unsigned int type)
{
	int i;
	bool found = false;

	for (i = 0; i < data->port_count && !found; i++) {
		if (data->ports[i].type == type)
			found = true;
	}

	igt_require_f(found, "No port of type %s was found\n",
		      kmstest_connector_type_str(type));
}

static drmModeConnection
reprobe_connector(data_t *data, const struct chamelium_port *port)
{
	drmModeConnector *connector;
	drmModeConnection status;

	igt_debug("Reprobing %s...\n", port->connector_name);
	connector = drmModeGetConnector(data->drm_fd, port->connector_id);
	igt_assert(connector);
	status = connector->connection;

	drmModeFreeConnector(connector);
	return status;
}

static void
wait_for_connector(data_t *data, const struct chamelium_port *port,
		   drmModeConnection status)
{
	bool finished = false;

	igt_debug("Waiting for %s to %sconnect...\n", port->connector_name,
		  status == DRM_MODE_DISCONNECTED ? "dis" : "");

	/*
	 * Rely on simple reprobing so we don't fail tests that don't require
	 * that hpd events work in the event that hpd doesn't work on the system
	 */
	igt_until_timeout(HOTPLUG_TIMEOUT) {
		if (reprobe_connector(data, port) == status) {
			finished = true;
			return;
		}

		sleep(1);
	}

	igt_assert(finished);
}

static void
reset_state(data_t *data, const struct chamelium_port *port)
{
	igt_reset_connectors();
	chamelium_reset(data->chamelium);
	wait_for_connector(data, port, DRM_MODE_DISCONNECTED);
}

static void
test_basic_hotplug(data_t *data, const struct chamelium_port *port)
{
	int i;

	reset_state(data, port);

	igt_watch_hotplug();

	for (i = 0; i < 15; i++) {
		igt_flush_hotplugs();

		/* Check if we get a sysfs hotplug event */
		chamelium_plug(data->chamelium, port->id);
		igt_assert(igt_hotplug_detected(HOTPLUG_TIMEOUT));
		igt_assert(reprobe_connector(data, port) == DRM_MODE_CONNECTED);

		igt_flush_hotplugs();

		/* Now check if we get a hotplug from disconnection */
		chamelium_unplug(data->chamelium, port->id);
		igt_assert(igt_hotplug_detected(HOTPLUG_TIMEOUT));
		igt_assert(reprobe_connector(data, port) ==
			   DRM_MODE_DISCONNECTED);

		/* Sleep so we don't accidentally cause an hpd storm */
		sleep(1);
	}
}

static void
test_edid_read(data_t *data, const struct chamelium_port *port,
	       int edid_id, const unsigned char *edid)
{
	drmModePropertyBlobPtr edid_blob = NULL;
	uint64_t edid_blob_id;

	reset_state(data, port);

	chamelium_port_set_edid(data->chamelium, port->id, edid_id);
	chamelium_plug(data->chamelium, port->id);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);

	igt_assert(kmstest_get_property(data->drm_fd, port->connector_id,
					DRM_MODE_OBJECT_CONNECTOR, "EDID", NULL,
					&edid_blob_id, NULL));
	igt_assert(edid_blob = drmModeGetPropertyBlob(data->drm_fd,
						      edid_blob_id));

	/* Compare the EDID from the connector to what we expect */
	igt_assert(memcmp(edid, edid_blob->data, EDID_LENGTH) == 0);

	drmModeFreePropertyBlob(edid_blob);
}

static void
test_suspend_resume_hpd(data_t *data, const struct chamelium_port *port,
			enum igt_suspend_state state,
			enum igt_suspend_test test)
{
	int delay = 7;

	igt_skip_without_suspend_support(state, test);
	reset_state(data, port);
	igt_watch_hotplug();

	igt_set_autoresume_delay(15);

	/* Make sure we notice new connectors after resuming */
	chamelium_async_hpd_pulse_start(data->chamelium, port->id, false, delay);
	igt_system_suspend_autoresume(state, test);
	chamelium_async_hpd_pulse_finish(data->chamelium);

	igt_assert(igt_hotplug_detected(HOTPLUG_TIMEOUT));
	igt_assert(reprobe_connector(data, port) == DRM_MODE_CONNECTED);

	igt_flush_hotplugs();

	/* Now make sure we notice disconnected connectors after resuming */
	chamelium_async_hpd_pulse_start(data->chamelium, port->id, true, delay);
	igt_system_suspend_autoresume(state, test);
	chamelium_async_hpd_pulse_finish(data->chamelium);

	igt_assert(igt_hotplug_detected(HOTPLUG_TIMEOUT));
	igt_assert(reprobe_connector(data, port) == DRM_MODE_DISCONNECTED);
}

static void
test_suspend_resume_edid_change(data_t *data, const struct chamelium_port *port,
				enum igt_suspend_state state,
				enum igt_suspend_test test,
				int edid_id,
				int alt_edid_id)
{
	igt_skip_without_suspend_support(state, test);
	reset_state(data, port);
	igt_watch_hotplug();

	/* First plug in the port */
	chamelium_port_set_edid(data->chamelium, port->id, edid_id);
	chamelium_plug(data->chamelium, port->id);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);

	igt_flush_hotplugs();

	/*
	 * Change the edid before we suspend. On resume, the machine should
	 * notice the EDID change and fire a hotplug event.
	 */
	chamelium_port_set_edid(data->chamelium, port->id, alt_edid_id);

	igt_system_suspend_autoresume(state, test);
	igt_assert(igt_hotplug_detected(HOTPLUG_TIMEOUT));
}

static void
test_display(data_t *data, const struct chamelium_port *port)
{
	igt_display_t display;
	igt_output_t *output;
	igt_plane_t *primary;
	struct igt_fb fb;
	drmModeRes *res;
	drmModeModeInfo *mode;
	drmModeConnector *connector;
	uint32_t crtc_id;
	int fb_id;

	reset_state(data, port);

	chamelium_plug(data->chamelium, port->id);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);
	igt_assert(res = drmModeGetResources(data->drm_fd));
	kmstest_unset_all_crtcs(data->drm_fd, res);

	igt_display_init(&display, data->drm_fd);

	/* Find the output struct for this connector */
	for_each_connected_output(&display, output) {
		if (output->config.connector->connector_id ==
		    port->connector_id)
			break;
	}

	connector = drmModeGetConnectorCurrent(data->drm_fd,
					       port->connector_id);

	/* Find a spare CRTC to use for the display */
	crtc_id = kmstest_find_crtc_for_connector(data->drm_fd, res, connector,
						  0);

	/* Setup the display */
	igt_output_set_pipe(output, kmstest_get_pipe_from_crtc_id(data->drm_fd,
								  crtc_id));
	mode = igt_output_get_mode(output);
	primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	fb_id = igt_create_pattern_fb(data->drm_fd,
				      mode->hdisplay,
				      mode->vdisplay,
				      DRM_FORMAT_XRGB8888,
				      LOCAL_DRM_FORMAT_MOD_NONE,
				      &fb);
	igt_assert(fb_id > 0);
	igt_plane_set_fb(primary, &fb);

	igt_display_commit(&display);

	igt_assert(chamelium_port_wait_video_input_stable(data->chamelium,
							  port->id,
							  HOTPLUG_TIMEOUT));

	drmModeFreeResources(res);
	drmModeFreeConnector(connector);
	igt_display_fini(&display);
}

static void
test_hpd_without_ddc(data_t *data, const struct chamelium_port *port)
{
	reset_state(data, port);
	igt_watch_hotplug();

	/* Disable the DDC on the connector and make sure we still get a
	 * hotplug
	 */
	chamelium_port_set_ddc_state(data->chamelium, port->id, false);
	chamelium_plug(data->chamelium, port->id);

	igt_assert(igt_hotplug_detected(HOTPLUG_TIMEOUT));
	igt_assert(reprobe_connector(data, port) == DRM_MODE_CONNECTED);
}

#define for_each_port(p, port)             \
	for (p = 0, port = &data.ports[p]; \
	     p < data.port_count;          \
	     p++, port = &data.ports[p])   \

#define connector_subtest(name__, type__) \
	igt_subtest(name__)               \
		for_each_port(p, port)    \
			if (port->type == DRM_MODE_CONNECTOR_ ## type__)

static data_t data;

igt_main
{
	const struct chamelium_port *port;
	int edid_id, alt_edid_id, p;

	igt_fixture {
		igt_skip_on_simulation();

		data.drm_fd = drm_open_driver_master(DRIVER_ANY);
		data.chamelium = chamelium_init(data.drm_fd);
		igt_require(data.chamelium);

		data.ports = chamelium_get_ports(data.chamelium,
						 &data.port_count);

		edid_id = chamelium_new_edid(data.chamelium,
					     igt_kms_get_base_edid());
		alt_edid_id = chamelium_new_edid(data.chamelium,
						 igt_kms_get_alt_edid());

		/* So fbcon doesn't try to reprobe things itself */
		kmstest_set_vt_graphics_mode();
	}

	igt_subtest_group {
		igt_fixture {
			require_connector_present(
			    &data, DRM_MODE_CONNECTOR_DisplayPort);
		}

		connector_subtest("dp-hpd", DisplayPort)
			test_basic_hotplug(&data, port);

		connector_subtest("dp-edid-read", DisplayPort) {
			test_edid_read(&data, port, edid_id,
				       igt_kms_get_base_edid());
			test_edid_read(&data, port, alt_edid_id,
				       igt_kms_get_alt_edid());
		}

		connector_subtest("dp-hpd-after-suspend", DisplayPort)
			test_suspend_resume_hpd(&data, port,
						SUSPEND_STATE_MEM,
						SUSPEND_TEST_NONE);

		connector_subtest("dp-hpd-after-hibernate", DisplayPort)
			test_suspend_resume_hpd(&data, port,
						SUSPEND_STATE_DISK,
						SUSPEND_TEST_DEVICES);

		connector_subtest("dp-edid-change-during-suspend", DisplayPort)
			test_suspend_resume_edid_change(&data, port,
							SUSPEND_STATE_MEM,
							SUSPEND_TEST_NONE,
							edid_id, alt_edid_id);

		connector_subtest("dp-edid-change-during-hibernate", DisplayPort)
			test_suspend_resume_edid_change(&data, port,
							SUSPEND_STATE_DISK,
							SUSPEND_TEST_DEVICES,
							edid_id, alt_edid_id);

		connector_subtest("dp-display", DisplayPort)
			test_display(&data, port);
	}

	igt_subtest_group {
		igt_fixture {
			require_connector_present(
			    &data, DRM_MODE_CONNECTOR_HDMIA);
		}

		connector_subtest("hdmi-hpd", HDMIA)
			test_basic_hotplug(&data, port);

		connector_subtest("hdmi-edid-read", HDMIA) {
			test_edid_read(&data, port, edid_id,
				       igt_kms_get_base_edid());
			test_edid_read(&data, port, alt_edid_id,
				       igt_kms_get_alt_edid());
		}

		connector_subtest("hdmi-hpd-after-suspend", HDMIA)
			test_suspend_resume_hpd(&data, port,
						SUSPEND_STATE_MEM,
						SUSPEND_TEST_NONE);

		connector_subtest("hdmi-hpd-after-hibernate", HDMIA)
			test_suspend_resume_hpd(&data, port,
						SUSPEND_STATE_DISK,
						SUSPEND_TEST_DEVICES);

		connector_subtest("hdmi-edid-change-during-suspend", HDMIA)
			test_suspend_resume_edid_change(&data, port,
							SUSPEND_STATE_MEM,
							SUSPEND_TEST_NONE,
							edid_id, alt_edid_id);

		connector_subtest("hdmi-edid-change-during-hibernate", HDMIA)
			test_suspend_resume_edid_change(&data, port,
							SUSPEND_STATE_DISK,
							SUSPEND_TEST_DEVICES,
							edid_id, alt_edid_id);

		connector_subtest("hdmi-display", HDMIA)
			test_display(&data, port);
	}

	igt_subtest_group {
		igt_fixture {
			require_connector_present(
			    &data, DRM_MODE_CONNECTOR_VGA);
		}

		connector_subtest("vga-hpd", VGA)
			test_basic_hotplug(&data, port);

		connector_subtest("vga-edid-read", VGA) {
			test_edid_read(&data, port, edid_id,
				       igt_kms_get_base_edid());
			test_edid_read(&data, port, alt_edid_id,
				       igt_kms_get_alt_edid());
		}

		/* FIXME: Right now there isn't a way to do any sort of delayed
		 * psuedo-hotplug with VGA, so testing detection after a
		 * suspend/resume cycle isn't possible yet
		 */

		connector_subtest("vga-hpd-without-ddc", VGA)
			test_hpd_without_ddc(&data, port);

		connector_subtest("vga-display", VGA)
			test_display(&data, port);
	}
}
