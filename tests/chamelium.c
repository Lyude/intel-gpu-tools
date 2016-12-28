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
	struct chamelium *chamelium;
	struct chamelium_port **ports;
	int port_count;

	struct udev_monitor *mon;
	igt_display_t display;

	int edid_id;
	int alt_edid_id;
} data_t;

#define HOTPLUG_TIMEOUT 20 /* seconds */
#define CHAMELIUM_CHILL_TIME (700 * 1000) /* microseconds */

/* Pre-calculated CRCs for the pattern fb, for all the modes in the default
 * chamelium edid
 */
struct crc_entry {
	int width;
	int height;
	igt_crc_t crc;
};
struct crc_table {
	unsigned int connector_type;
	const struct crc_entry *entries;
	size_t len;
};

#define CRC_ENTRY(w_, h_, ...) \
	{ w_, h_, { 1, true, 4, { __VA_ARGS__ } } }

static const struct crc_entry pattern_fb_crcs_dp[] = {
	/*CRC_ENTRY(1920, 1080, 0xb223, 0x40b1, 0xe81b, 0x856f),*/
	CRC_ENTRY(1920, 1080, 0xf859, 0xa751, 0x8c81, 0x45a1),
	CRC_ENTRY(1600, 1200, 0xd752, 0x313b, 0xe034, 0x8a36),
	CRC_ENTRY(1680, 1050, 0x4284, 0xc6b6, 0x4d6a, 0x4854),
	CRC_ENTRY(1280, 1024, 0x4118, 0xe738, 0x7fa8, 0xd6cc),
	CRC_ENTRY(1440,  900, 0x4ba6, 0x9db8, 0x5a22, 0xa356),
	CRC_ENTRY(1280,  960, 0x7ea9, 0x58d5, 0x06c1, 0xcd8e),
	CRC_ENTRY(1360,  768, 0x6888, 0x805f, 0xb33c, 0x5bba),
	CRC_ENTRY(1280,  800, 0x4fab, 0x01ba, 0xe333, 0x6e63),
	CRC_ENTRY(1152,  864, 0xb0ad, 0x5143, 0xae08, 0xc30b),
	CRC_ENTRY(1280,  720, 0x21c9, 0xcb46, 0x8f56, 0xfd5c),
	CRC_ENTRY(1024,  768, 0x85e5, 0xf0cd, 0xafe3, 0x7f18),
	CRC_ENTRY( 832,  624, 0xa968, 0x729e, 0x6768, 0x2de4),
	CRC_ENTRY( 800,  600, 0x6b39, 0x32b6, 0x831a, 0xb03e),
	CRC_ENTRY( 720,  480, 0x7dc6, 0xbd08, 0x0309, 0x4e6b),
	CRC_ENTRY( 640,  480, 0xa121, 0x2473, 0xb150, 0x8c47),
	CRC_ENTRY( 720,  400, 0xf280, 0xa7bf, 0xc20d, 0x1950),
};

static const struct crc_entry pattern_fb_crcs_hdmi[] = {
	CRC_ENTRY(1920, 1080, 0xf859, 0xa751, 0x8c81, 0x45a1),
	CRC_ENTRY(1600, 1200, 0xd752, 0x313b, 0xe034, 0x8a36),
	CRC_ENTRY(1680, 1050, 0x4284, 0xc6b6, 0x4d6a, 0x4854),
	CRC_ENTRY(1280, 1024, 0x4118, 0xe738, 0x7fa8, 0xd6cc),
	CRC_ENTRY(1440,  900, 0x4ba6, 0x9db8, 0x5a22, 0xa356),
	CRC_ENTRY(1280,  960, 0x7ea9, 0x58d5, 0x06c1, 0xcd8e),
	CRC_ENTRY(1360,  768, 0x6888, 0x805f, 0xb33c, 0x5bba),
	CRC_ENTRY(1280,  800, 0x4fab, 0x01ba, 0xe333, 0x6e63),
	CRC_ENTRY(1152,  864, 0xb0ad, 0x5143, 0xae08, 0xc30b),
	CRC_ENTRY(1280,  720, 0xcec2, 0x4246, 0x6cfd, 0xeb43),
	CRC_ENTRY(1024,  768, 0x85e5, 0xf0cd, 0xafe3, 0x7f18),
	CRC_ENTRY( 832,  624, 0xa968, 0x729e, 0x6768, 0x2de4),
	CRC_ENTRY( 800,  600, 0x6b39, 0x32b6, 0x831a, 0xb03e),
	CRC_ENTRY( 720,  480, 0x4306, 0xd501, 0x1eba, 0xf784),
	CRC_ENTRY( 640,  480, 0xa121, 0x2473, 0xb150, 0x8c47),
	CRC_ENTRY( 720,  400, 0xf280, 0xa7bf, 0xc20d, 0x1950),
};
#undef CRC_ENTRY

static const struct crc_table crc_table[] = {
	{
		.connector_type = DRM_MODE_CONNECTOR_DisplayPort,
		.entries = pattern_fb_crcs_dp,
		.len = ARRAY_SIZE(pattern_fb_crcs_dp),
	},
	{
		.connector_type = DRM_MODE_CONNECTOR_HDMIA,
		.entries = pattern_fb_crcs_hdmi,
		.len = ARRAY_SIZE(pattern_fb_crcs_hdmi),
	},
};

static const igt_crc_t *
get_precalculated_crc(struct chamelium_port *port, int w, int h)
{
	int i;
	const struct crc_table *table = NULL;
	const struct crc_entry *entry = NULL;

	/* Lookup the CRC table for this type */
	for (i = 0; i < ARRAY_SIZE(crc_table); i++) {
		if (crc_table[i].connector_type ==
		    chamelium_port_get_type(port)) {
			table = &crc_table[i];
			break;
		}
	}
	if (!table)
		return NULL;

	/* Now lookup the CRC for this resolution */
	for (i = 0; i < table->len && !entry; i++) {
		if (table->entries[i].width == w &&
		    table->entries[i].height == h)
			entry = &table->entries[i];
	}
	if (!entry)
		return NULL;

	return &entry->crc;
}

static void
require_connector_present(data_t *data, unsigned int type)
{
	int i;
	bool found = false;

	for (i = 0; i < data->port_count && !found; i++) {
		if (chamelium_port_get_type(data->ports[i]) == type)
			found = true;
	}

	igt_require_f(found, "No port of type %s was found\n",
		      kmstest_connector_type_str(type));
}

static drmModeConnection
reprobe_connector(data_t *data, struct chamelium_port *port)
{
	drmModeConnector *connector;
	drmModeConnection status;

	igt_debug("Reprobing %s...\n", chamelium_port_get_name(port));
	connector = chamelium_port_get_connector(data->chamelium, port, true);
	igt_assert(connector);
	status = connector->connection;

	drmModeFreeConnector(connector);
	return status;
}

static void
wait_for_connector(data_t *data, struct chamelium_port *port,
		   drmModeConnection status)
{
	bool finished = false;

	igt_debug("Waiting for %s to %sconnect...\n",
		  chamelium_port_get_name(port),
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
reset_state(data_t *data, struct chamelium_port *port)
{
	igt_reset_connectors();
	chamelium_reset(data->chamelium);
	wait_for_connector(data, port, DRM_MODE_DISCONNECTED);
	sleep(1);
}

static void
test_basic_hotplug(data_t *data, struct chamelium_port *port)
{
	int i;

	reset_state(data, port);

	igt_watch_hotplug();

	for (i = 0; i < 15; i++) {
		igt_flush_hotplugs(data->mon);

		/* Check if we get a sysfs hotplug event */
		chamelium_plug(data->chamelium, port);
		igt_assert(igt_hotplug_detected(data->mon, HOTPLUG_TIMEOUT));
		igt_assert(reprobe_connector(data, port) == DRM_MODE_CONNECTED);

		igt_flush_hotplugs(data->mon);

		/* Now check if we get a hotplug from disconnection */
		chamelium_unplug(data->chamelium, port);
		igt_assert(igt_hotplug_detected(data->mon, HOTPLUG_TIMEOUT));
		igt_assert(reprobe_connector(data, port) ==
			   DRM_MODE_DISCONNECTED);

		/* Sleep so we don't accidentally cause an hpd storm */
		sleep(1);
	}
}

static void
test_edid_read(data_t *data, struct chamelium_port *port,
	       int edid_id, const unsigned char *edid)
{
	drmModePropertyBlobPtr edid_blob = NULL;
	drmModeConnector *connector = chamelium_port_get_connector(
	    data->chamelium, port, false);
	uint64_t edid_blob_id;

	reset_state(data, port);

	chamelium_port_set_edid(data->chamelium, port, edid_id);
	chamelium_plug(data->chamelium, port);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);

	igt_assert(kmstest_get_property(data->display.drm_fd, connector->connector_id,
					DRM_MODE_OBJECT_CONNECTOR, "EDID", NULL,
					&edid_blob_id, NULL));
	igt_assert(edid_blob = drmModeGetPropertyBlob(data->display.drm_fd,
						      edid_blob_id));

	/* Compare the EDID from the connector to what we expect */
	igt_assert(memcmp(edid, edid_blob->data, EDID_LENGTH) == 0);

	drmModeFreePropertyBlob(edid_blob);
	drmModeFreeConnector(connector);
}

static void
test_suspend_resume_hpd(data_t *data, struct chamelium_port *port,
			enum igt_suspend_state state,
			enum igt_suspend_test test)
{
	int delay = 7;

	igt_skip_without_suspend_support(state, test);
	reset_state(data, port);
	igt_watch_hotplug();

	igt_set_autoresume_delay(15);

	/* Make sure we notice new connectors after resuming */
	chamelium_async_hpd_pulse_start(data->chamelium, port, false, delay);
	igt_system_suspend_autoresume(state, test);
	chamelium_async_hpd_pulse_finish(data->chamelium);

	igt_assert(igt_hotplug_detected(data->mon, HOTPLUG_TIMEOUT));
	igt_assert(reprobe_connector(data, port) == DRM_MODE_CONNECTED);

	igt_flush_hotplugs(data->mon);

	/* Now make sure we notice disconnected connectors after resuming */
	chamelium_async_hpd_pulse_start(data->chamelium, port, true, delay);
	igt_system_suspend_autoresume(state, test);
	chamelium_async_hpd_pulse_finish(data->chamelium);

	igt_assert(igt_hotplug_detected(data->mon, HOTPLUG_TIMEOUT));
	igt_assert(reprobe_connector(data, port) == DRM_MODE_DISCONNECTED);
}

static void
test_suspend_resume_edid_change(data_t *data, struct chamelium_port *port,
				enum igt_suspend_state state,
				enum igt_suspend_test test,
				int edid_id,
				int alt_edid_id)
{
	igt_skip_without_suspend_support(state, test);
	reset_state(data, port);
	igt_watch_hotplug();

	/* First plug in the port */
	chamelium_port_set_edid(data->chamelium, port, edid_id);
	chamelium_plug(data->chamelium, port);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);

	igt_flush_hotplugs(data->mon);

	/*
	 * Change the edid before we suspend. On resume, the machine should
	 * notice the EDID change and fire a hotplug event.
	 */
	chamelium_port_set_edid(data->chamelium, port, alt_edid_id);

	igt_system_suspend_autoresume(state, test);
	igt_assert(igt_hotplug_detected(data->mon, HOTPLUG_TIMEOUT));
}

static igt_output_t *
prepare_output(data_t *data,
	       struct chamelium_port *port)
{
	igt_output_t *output;
	drmModeRes *res;
	drmModeConnector *connector =
		chamelium_port_get_connector(data->chamelium, port, false);
	bool found = false;

	chamelium_reset(data->chamelium);
	wait_for_connector(data, port, DRM_MODE_DISCONNECTED);

	igt_assert(res = drmModeGetResources(data->display.drm_fd));
	kmstest_unset_all_crtcs(data->display.drm_fd, res);

	/* The chamelium's default EDID has a lot of resolutions, way more then
	 * we need to test
	 */
	chamelium_port_set_edid(data->chamelium, port, data->edid_id);

	chamelium_plug(data->chamelium, port);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);

	igt_display_refresh(&data->display);
	for_each_connected_output(&data->display, output) {
		if (output->config.connector->connector_id ==
		    connector->connector_id) {
			found = true;
			break;
		}
	}
	igt_assert(found);
	igt_assert(output->config.connector->count_modes);

	igt_assert(kmstest_probe_connector_config(
		data->display.drm_fd, connector->connector_id, ~0,
		&output->config));
	igt_output_set_pipe(output, output->config.pipe);

	drmModeFreeConnector(connector);
	drmModeFreeResources(res);

	return output;
}

static void
enable_output(data_t *data,
	      struct chamelium_port *port,
	      igt_output_t *output,
	      drmModeModeInfo *mode,
	      struct igt_fb *fb)
{
	igt_display_t *display = output->display;
	igt_plane_t *primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	igt_plane_set_size(primary, mode->hdisplay, mode->vdisplay);
	igt_plane_set_fb(primary, fb);
	igt_output_override_mode(output, mode);

	/*
	 * Unfortunately it's very easy to upset the Chamelium with quick
	 * successive resolution changes. So cool down for a second before
	 * turning on the display
	 */
	usleep(CHAMELIUM_CHILL_TIME);

	chamelium_plug(data->chamelium, port);
	wait_for_connector(data, port, DRM_MODE_CONNECTED);
	igt_display_commit(display);

	igt_assert(chamelium_port_wait_video_input_stable(
		data->chamelium, port, HOTPLUG_TIMEOUT));
}

static void
disable_output(data_t *data,
	       struct chamelium_port *port,
	       igt_output_t *output)
{
	igt_display_t *display = output->display;
	igt_plane_t *primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	/* Disable the display */
	igt_plane_set_fb(primary, NULL);
	igt_display_commit(display);

	chamelium_unplug(data->chamelium, port);
	wait_for_connector(data, port, DRM_MODE_DISCONNECTED);
}

static void
test_display_resolution(data_t *data, struct chamelium_port *port)
{
	igt_output_t *output;
	igt_plane_t *primary;
	struct igt_fb fb;
	drmModeModeInfo *mode;
	drmModeConnector *connector;
	int fb_id, i, x, y;

	output = prepare_output(data, port);
	connector = chamelium_port_get_connector(data->chamelium, port, false);
	primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	for (i = 0; i < connector->count_modes; i++) {
		mode = &connector->modes[i];
		fb_id = igt_create_pattern_fb(data->display.drm_fd,
					      mode->hdisplay,
					      mode->vdisplay,
					      DRM_FORMAT_XRGB8888,
					      LOCAL_DRM_FORMAT_MOD_NONE,
					      &fb);
		igt_assert(fb_id > 0);

		enable_output(data, port, output, mode, &fb);

		chamelium_port_get_resolution(data->chamelium, port, &x, &y);
		igt_assert_eq(mode->hdisplay, x);
		igt_assert_eq(mode->vdisplay, y);

		disable_output(data, port, output);
		igt_remove_fb(data->display.drm_fd, &fb);
	}

	drmModeFreeConnector(connector);
}

static void
test_display_crc_single(data_t *data, struct chamelium_port *port)
{
	igt_output_t *output;
	igt_plane_t *primary;
	igt_crc_t *crc;
	const igt_crc_t *expected_crc;
	struct igt_fb fb;
	drmModeModeInfo *mode;
	drmModeConnector *connector;
	int fb_id, i;

	output = prepare_output(data, port);
	connector = chamelium_port_get_connector(data->chamelium, port, false);
	primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	for (i = 0; i < connector->count_modes; i++) {
		mode = &connector->modes[i];
		fb_id = igt_create_pattern_fb(data->display.drm_fd,
					      mode->hdisplay,
					      mode->vdisplay,
					      DRM_FORMAT_XRGB8888,
					      LOCAL_DRM_FORMAT_MOD_NONE,
					      &fb);
		igt_assert(fb_id > 0);

		enable_output(data, port, output, mode, &fb);

		expected_crc = get_precalculated_crc(port,
						     mode->hdisplay,
						     mode->vdisplay);
		if (!expected_crc) {
			igt_warn("No precalculated CRC found for %dx%d, skipping CRC check\n",
				 mode->hdisplay, mode->vdisplay);
			goto next;
		}

		igt_debug("Testing single CRC fetch\n");
		crc = chamelium_get_crc_for_area(data->chamelium, port,
						 0, 0, 0, 0);
		igt_assert_crc_equal(crc, expected_crc);
		free(crc);

next:
		disable_output(data, port, output);
		igt_remove_fb(data->display.drm_fd, &fb);
	}

	drmModeFreeConnector(connector);
}

static void
test_display_crc_multiple(data_t *data, struct chamelium_port *port)
{
	igt_output_t *output;
	igt_plane_t *primary;
	igt_crc_t *crc;
	const igt_crc_t *expected_crc;
	struct igt_fb fb;
	drmModeModeInfo *mode;
	drmModeConnector *connector;
	int fb_id, i, j, frame_cnt, captured_frame_count;

	output = prepare_output(data, port);
	connector = chamelium_port_get_connector(data->chamelium, port, false);
	primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	for (i = 0; i < connector->count_modes; i++) {
		mode = &connector->modes[i];
		fb_id = igt_create_pattern_fb(data->display.drm_fd,
					      mode->hdisplay,
					      mode->vdisplay,
					      DRM_FORMAT_XRGB8888,
					      LOCAL_DRM_FORMAT_MOD_NONE,
					      &fb);
		igt_assert(fb_id > 0);

		enable_output(data, port, output, mode, &fb);

		expected_crc = get_precalculated_crc(port, mode->hdisplay,
						     mode->vdisplay);
		if (!expected_crc) {
			igt_warn("No precalculated CRC found for %dx%d, skipping CRC check\n",
				 mode->hdisplay, mode->vdisplay);
			goto next;
		}

		/* We want to keep the display running for a little bit, since
		 * there's always the potential the driver isn't able to keep
		 * the display running properly for very long
		 */
		frame_cnt = min(chamelium_get_frame_limit(data->chamelium, port,
							  mode->hdisplay,
							  mode->vdisplay), 60);
		chamelium_capture(data->chamelium, port, 0, 0, 0, 0, frame_cnt);
		crc = chamelium_read_captured_crcs(data->chamelium,
						   &captured_frame_count);

		igt_debug("Captured %d frames\n", captured_frame_count);
		for (j = 0; j < captured_frame_count; j++)
			igt_assert_crc_equal(&crc[j], expected_crc);
		free(crc);

next:
		disable_output(data, port, output);
		igt_remove_fb(data->display.drm_fd, &fb);
	}

	drmModeFreeConnector(connector);
}

static void
test_display_frame_dump(data_t *data, struct chamelium_port *port)
{
	igt_output_t *output;
	igt_plane_t *primary;
	struct igt_fb fb;
	struct chamelium_frame_dump *frame;
	drmModeModeInfo *mode;
	drmModeConnector *connector;
	int fb_id, i, j, frame_cnt;

	output = prepare_output(data, port);
	connector = chamelium_port_get_connector(data->chamelium, port, false);
	primary = igt_output_get_plane(output, IGT_PLANE_PRIMARY);
	igt_assert(primary);

	for (i = 0; i < connector->count_modes; i++) {
		mode = &connector->modes[i];
		fb_id = igt_create_pattern_fb(data->display.drm_fd,
					      mode->hdisplay,
					      mode->vdisplay,
					      DRM_FORMAT_XRGB8888,
					      LOCAL_DRM_FORMAT_MOD_NONE,
					      &fb);
		igt_assert(fb_id > 0);

		enable_output(data, port, output, mode, &fb);

		igt_debug("Reading frame dumps from Chamelium...\n");
		frame_cnt = min(chamelium_get_frame_limit(data->chamelium, port,
							  mode->hdisplay,
							  mode->vdisplay), 10);
		chamelium_capture(data->chamelium, port, 0, 0, 0, 0, frame_cnt);
		for (j = 0; j < frame_cnt; j++) {
			frame = chamelium_read_captured_frame(
			    data->chamelium, j);
			chamelium_assert_frame_eq(data->chamelium, frame, &fb);
			chamelium_destroy_frame_dump(frame);
		}

		disable_output(data, port, output);
		igt_remove_fb(data->display.drm_fd, &fb);
	}

	drmModeFreeConnector(connector);
}

static void
test_hpd_without_ddc(data_t *data, struct chamelium_port *port)
{
	reset_state(data, port);
	igt_watch_hotplug();

	/* Disable the DDC on the connector and make sure we still get a
	 * hotplug
	 */
	chamelium_port_set_ddc_state(data->chamelium, port, false);
	chamelium_plug(data->chamelium, port);

	igt_assert(igt_hotplug_detected(data->mon, HOTPLUG_TIMEOUT));
	igt_assert(reprobe_connector(data, port) == DRM_MODE_CONNECTED);
}

#define for_each_port(p, port)            \
	for (p = 0, port = data.ports[p]; \
	     p < data.port_count;         \
	     p++, port = data.ports[p])   \

#define connector_subtest(name__, type__)                    \
	igt_subtest(name__)                                  \
		for_each_port(p, port)                       \
			if (chamelium_port_get_type(port) == \
			    DRM_MODE_CONNECTOR_ ## type__)

static data_t data;

igt_main
{
	struct chamelium_port *port;
	int edid_id, alt_edid_id, p;

	igt_fixture {
		igt_skip_on_simulation();

		igt_display_init(&data.display,
				 drm_open_driver_master(DRIVER_ANY));
		data.chamelium = chamelium_init(&data.display);
		igt_require(data.chamelium);
		data.mon = igt_watch_hotplug();

		data.ports = chamelium_get_ports(data.chamelium,
						 &data.port_count);

		edid_id = chamelium_new_edid(data.chamelium,
					     igt_kms_get_base_edid());
		alt_edid_id = chamelium_new_edid(data.chamelium,
						 igt_kms_get_alt_edid());
		data.edid_id = edid_id;
		data.alt_edid_id = alt_edid_id;

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
			test_display_resolution(&data, port);

		connector_subtest("dp-display-crc-single", DisplayPort)
			test_display_crc_single(&data, port);

		connector_subtest("dp-display-crc-multiple", DisplayPort)
			test_display_crc_multiple(&data, port);

		connector_subtest("dp-display-frame-dump", DisplayPort)
			test_display_frame_dump(&data, port);
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
			test_display_resolution(&data, port);

		connector_subtest("hdmi-display-crc-single", HDMIA)
			test_display_crc_single(&data, port);

		connector_subtest("hdmi-display-crc-multiple", HDMIA)
			test_display_crc_multiple(&data, port);

		connector_subtest("hdmi-display-frame-dump", HDMIA)
			test_display_frame_dump(&data, port);
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
	}
}
