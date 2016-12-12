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
 *  Lyude Paul <lyude@redhat.com>
 */

#include "config.h"

#include <string.h>
#include <errno.h>
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>
#include <glib.h>

#include "igt.h"

#define check_rpc() \
	igt_assert_f(!env.fault_occurred, "Chamelium RPC call failed: %s\n", \
		     env.fault_string);

/**
 * SECTION:igt_chamelium
 * @short_description: Library for encorporating the Chamelium into igt tests
 * @title: Chamelium
 * @include: igt_chamelium.h
 *
 * This library contains helpers for using Chameliums in IGT tests. This allows
 * for tests to simulate more difficult tasks to automate such as display
 * hotplugging, faulty display behaviors, etc.
 *
 * More information on the Chamelium can be found
 * [on the ChromeOS project page](https://www.chromium.org/chromium-os/testing/chamelium).
 *
 * In order to run tests using the Chamelium, a valid configuration file must be
 * present.  The configuration file is a normal Glib keyfile (similar to Windows
 * INI) structured like so:
 *
 * |[<!-- language="plain" -->
 *	[Chamelium]
 *	URL=http://chameleon:9992 # The URL used for connecting to the Chamelium's RPC server
 *
 *	# The rest of the sections are used for defining connector mappings.
 *	# This is required so any tests using the Chamelium know which connector
 *	# on the test machine should be connected to each Chamelium port.
 *	#
 *	# In the event that any of these mappings are specified incorrectly,
 *	# any hotplugging tests for the incorrect connector mapping will fail.
 *
 *	[DP-1] # The name of the DRM connector
 *	ChameliumPortID=1 # The ID of the port on the Chamelium this connector is attached to
 *
 *	[HDMI-A-1]
 *	ChameliumPortID=3
 * ]|
 *
 * By default, this file is expected to exist in ~/.igt_chamelium_rc . The
 * directory for this can be overriden by setting the environment variable
 * %CHAMELIUM_CONFIG_PATH.
 */

/**
 * chamelium_ports:
 *
 * Contains information on all of the ports that are configured for use with the
 * Chamelium. This information is initialized when #chamelium_init is called.
 */
struct chamelium_port *chamelium_ports;

/**
 * chamelium_port_count:
 *
 * How many ports are configured for use by the Chamelium.
 */
int chamelium_port_count;

static const char *chamelium_url;
static xmlrpc_env env;

struct chamelium_edid {
	int id;
	struct igt_list link;
};
struct chamelium_edid *allocated_edids;

/**
 * chamelium_plug:
 * @id: The ID of the port on the chamelium to plug
 *
 * Simulate a display connector being plugged into the system using the
 * chamelium.
 */
void chamelium_plug(int id)
{
	xmlrpc_value *res;

	igt_debug("Plugging port %d\n", id);
	res = xmlrpc_client_call(&env, chamelium_url, "Plug", "(i)", id);
	check_rpc();

	xmlrpc_DECREF(res);
}

/**
 * chamelium_unplug:
 * @id: The ID of the port on the chamelium to unplug
 *
 * Simulate a display connector being unplugged from the system using the
 * chamelium.
 */
void chamelium_unplug(int id)
{
	xmlrpc_value *res;

	igt_debug("Unplugging port %d\n", id);
	res = xmlrpc_client_call(&env, chamelium_url, "Unplug", "(i)", id);
	check_rpc();

	xmlrpc_DECREF(res);
}

/**
 * chamelium_is_plugged:
 * @id: The ID of the port on the chamelium to check the status of
 *
 * Check whether or not the given port has been plugged into the system using
 * #chamelium_plug.
 *
 * Returns: %true if the connector is set to plugged in, %false otherwise.
 */
bool chamelium_is_plugged(int id)
{
	xmlrpc_value *res;
	xmlrpc_bool is_plugged;

	res = xmlrpc_client_call(&env, chamelium_url, "IsPlugged", "(i)", id);
	check_rpc();

	xmlrpc_read_bool(&env, res, &is_plugged);
	xmlrpc_DECREF(res);

	return is_plugged;
}

/**
 * chamelium_port_wait_video_input_stable:
 * @id: The ID of the port on the chamelium to check the status of
 * @timeout_secs: How long to wait for a video signal to appear before timing
 * out
 *
 * Waits for a video signal to appear on the given port. This is useful for
 * checking whether or not we've setup a monitor correctly.
 *
 * Returns: %true if a video signal was detected, %false if we timed out
 */
bool chamelium_port_wait_video_input_stable(int id, int timeout_secs)
{
	xmlrpc_value *res;
	xmlrpc_bool is_on;

	igt_debug("Waiting for video input to stabalize on port %d\n", id);

	res = xmlrpc_client_call(&env, chamelium_url, "WaitVideoInputStable",
				 "(ii)", id, timeout_secs);
	check_rpc();

	xmlrpc_read_bool(&env, res, &is_on);
	xmlrpc_DECREF(res);

	return is_on;
}

/**
 * chamelium_fire_hpd_pulses:
 * @id: The ID of the port to fire hotplug pulses on
 * @width_msec: How long each pulse should last
 * @count: The number of pulses to send
 *
 * A convienence function for sending multiple hotplug pulses to the system.
 * The pulses start at low (e.g. connector is disconnected), and then alternate
 * from high (e.g. connector is plugged in) to low. This is the equivalent of
 * repeatedly calling #chamelium_plug and #chamelium_unplug, waiting
 * @width_msec between each call.
 *
 * If @count is even, the last pulse sent will be high, and if it's odd then it
 * will be low. Resetting the HPD line back to it's previous state, if desired,
 * is the responsibility of the caller.
 */
void chamelium_fire_hpd_pulses(int id, int width_msec, int count)
{
	xmlrpc_value *pulse_widths = xmlrpc_array_new(&env),
		     *width = xmlrpc_int_new(&env, width_msec), *res;
	int i;

	igt_debug("Firing %d HPD pulses with width of %d msec on id %d\n",
		  count, width_msec, id);

	for (i = 0; i < count; i++)
		xmlrpc_array_append_item(&env, pulse_widths, width);

	res = xmlrpc_client_call(&env, chamelium_url, "FireMixedHpdPulses",
				 "(iA)", id, pulse_widths);
	check_rpc();

	xmlrpc_DECREF(res);
	xmlrpc_DECREF(width);
	xmlrpc_DECREF(pulse_widths);
}

/**
 * chamelium_fire_mixed_hpd_pulses:
 * @id: The ID of the port to fire hotplug pulses on
 * @...: The length of each pulse in milliseconds, terminated with a %0
 *
 * Does the same thing as #chamelium_fire_hpd_pulses, but allows the caller to
 * specify the length of each individual pulse.
 */
void chamelium_fire_mixed_hpd_pulses(int id, ...)
{
	va_list args;
	xmlrpc_value *pulse_widths = xmlrpc_array_new(&env), *width, *res;
	int arg;

	igt_debug("Firing mixed HPD pulses on port %d\n", id);

	va_start(args, id);
	for (arg = va_arg(args, int); arg; arg = va_arg(args, int)) {
		width = xmlrpc_int_new(&env, arg);
		xmlrpc_array_append_item(&env, pulse_widths, width);
		xmlrpc_DECREF(width);
	}
	va_end(args);

	res = xmlrpc_client_call(&env, chamelium_url, "FireMixedHpdPulses",
				 "(iA)", id, pulse_widths);
	check_rpc();
	xmlrpc_DECREF(res);

	xmlrpc_DECREF(pulse_widths);
}

static void async_rpc_handler(const char *server_url, const char *method_name,
			      xmlrpc_value *param_array, void *user_data,
			      xmlrpc_env *fault, xmlrpc_value *result)
{
	/* We don't care about the responses */
}

/**
 * chamelium_async_hpd_pulse_start:
 * @id: The ID of the port to fire a hotplug pulse on
 * @high: Whether to fire a high pulse (e.g. simulate a connect), or a low
 * pulse (e.g. simulate a disconnect)
 * @delay_secs: How long to wait before sending the HPD pulse.
 *
 * Instructs the chamelium to send an hpd pulse after @delay_secs seconds have
 * passed, without waiting for the chamelium to finish. This is useful for
 * testing things such as hpd after a suspend/resume cycle, since we can't tell
 * the chamelium to send a hotplug at the same time that our system is
 * suspended.
 *
 * It is required that the user eventually call
 * #chamelium_async_hpd_pulse_finish, to clean up the leftover XML-RPC
 * responses from the chamelium.
 */
void chamelium_async_hpd_pulse_start(int id, bool high, int delay_secs)
{
	xmlrpc_value *pulse_widths = xmlrpc_array_new(&env), *width;

	/* TODO: Actually implement something in the chameleon server to allow
	 * for delayed actions such as hotplugs. This would work a bit better
	 * and allow us to test suspend/resume on ports without hpd like VGA
	 */

	igt_debug("Sending HPD pulse (%s) on port %d with %d second delay\n",
		  high ? "high->low" : "low->high", id, delay_secs);

	/* If we're starting at high, make the first pulse width 0 so we keep
	 * the port connected */
	if (high) {
		width = xmlrpc_int_new(&env, 0);
		xmlrpc_array_append_item(&env, pulse_widths, width);
		xmlrpc_DECREF(width);
	}

	width = xmlrpc_int_new(&env, delay_secs * 1000);
	xmlrpc_array_append_item(&env, pulse_widths, width);
	xmlrpc_DECREF(width);

	xmlrpc_client_call_asynch(chamelium_url, "FireMixedHpdPulses",
				  async_rpc_handler, NULL, "(iA)",
				  id, pulse_widths);
	xmlrpc_DECREF(pulse_widths);
}

/**
 * chamelium_async_hpd_pulse_finish:
 *
 * Waits for any asynchronous RPC started by #chamelium_async_hpd_pulse_start
 * to complete, and then cleans up any leftover responses from the chamelium.
 * If all of the RPC calls have already completed, this function returns
 * immediately.
 */
void chamelium_async_hpd_pulse_finish(void)
{
	xmlrpc_client_event_loop_finish_asynch();
}

/**
 * chamelium_new_edid:
 * @edid: The edid blob to upload to the chamelium
 *
 * Uploads and registers a new EDID with the chamelium. The EDID will be
 * destroyed automatically when #chamelium_deinit is called.
 *
 * Returns: The ID of the EDID uploaded to the chamelium.
 */
int chamelium_new_edid(const unsigned char *edid)
{
	xmlrpc_value *res;
	struct chamelium_edid *allocated_edid;
	int edid_id;

	res = xmlrpc_client_call(&env, chamelium_url, "CreateEdid",
				 "(6)", edid, EDID_LENGTH);
	check_rpc();

	xmlrpc_read_int(&env, res, &edid_id);
	xmlrpc_DECREF(res);

	allocated_edid = malloc(sizeof(struct chamelium_edid));
	igt_assert(allocated_edid);

	allocated_edid->id = edid_id;
	igt_list_init(&allocated_edid->link);

	if (allocated_edids) {
		igt_list_add(&allocated_edids->link, &allocated_edid->link);
	} else {
		allocated_edids = allocated_edid;
	}

	return edid_id;
}

static void chamelium_destroy_edid(int edid_id)
{
	xmlrpc_value *res;

	res = xmlrpc_client_call(&env, chamelium_url, "DestroyEdid",
				 "(i)", edid_id);
	check_rpc();

	xmlrpc_DECREF(res);
}

/**
 * chamelium_port_set_edid:
 * @id: The ID of the port to set the EDID on
 * @edid_id: The ID of an EDID on the chamelium created with
 * #chamelium_new_edid, or 0 to disable the EDID on the port
 *
 * Sets a port on the chamelium to use the specified EDID. This does not fire a
 * hotplug pulse on it's own, and merely changes what EDID the chamelium port
 * will report to us the next time we probe it. Users will need to reprobe the
 * connectors themselves if they want to see the EDID reported by the port
 * change.
 */
void chamelium_port_set_edid(int id, int edid_id)
{
	xmlrpc_value *res;

	res = xmlrpc_client_call(&env, chamelium_url, "ApplyEdid",
				 "(ii)", id, edid_id);
	check_rpc();

	xmlrpc_DECREF(res);
}

/**
 * chamelium_port_set_ddc_state:
 * @id: The ID of the port whose DDC bus we want to modify
 * @enabled: Whether or not to enable the DDC bus
 *
 * This disables the DDC bus (e.g. the i2c line on the connector that gives us
 * an EDID) of the specified port on the chamelium. This is useful for testing
 * behavior on legacy connectors such as VGA, where the presence of a DDC bus
 * is not always guaranteed.
 */
void chamelium_port_set_ddc_state(int port, bool enabled)
{
	xmlrpc_value *res;

	igt_debug("%sabling DDC bus on port %d\n",
		  enabled ? "En" : "Dis", port);

	res = xmlrpc_client_call(&env, chamelium_url, "SetDdcState",
				 "(ib)", port, enabled);
	check_rpc();

	xmlrpc_DECREF(res);
}

/**
 * chamelium_port_get_ddc_state:
 * @id: The ID of the port whose DDC bus we want to check the status of
 *
 * Check whether or not the DDC bus on the specified chamelium port is enabled
 * or not.
 *
 * Returns: %true if the DDC bus is enabled, %false otherwise.
 */
bool chamelium_port_get_ddc_state(int id)
{
	xmlrpc_value *res;
	xmlrpc_bool enabled;

	res = xmlrpc_client_call(&env, chamelium_url, "IsDdcEnabled",
				 "(i)", id);
	check_rpc();

	xmlrpc_read_bool(&env, res, &enabled);

	xmlrpc_DECREF(res);
	return enabled;
}

/**
 * chamelium_port_get_resolution:
 * @id: The ID of the port whose display resolution we want to check
 * @x: Where to store the horizontal resolution of the port
 * @y: Where to store the verical resolution of the port
 *
 * Check the current reported display resolution of the specified port on the
 * chamelium. This information is provided by the chamelium itself, not DRM.
 * Useful for verifying that we really are scanning out at the resolution we
 * think we are.
 */
void chamelium_port_get_resolution(int id, int *x, int *y)
{
	xmlrpc_value *res, *res_x, *res_y;

	res = xmlrpc_client_call(&env, chamelium_url, "DetectResolution",
				 "(i)", id);
	check_rpc();

	xmlrpc_array_read_item(&env, res, 0, &res_x);
	xmlrpc_array_read_item(&env, res, 1, &res_y);
	xmlrpc_read_int(&env, res_x, x);
	xmlrpc_read_int(&env, res_y, y);

	xmlrpc_DECREF(res_x);
	xmlrpc_DECREF(res_y);
	xmlrpc_DECREF(res);
}

static void crc_from_xml(xmlrpc_value *xml_crc, igt_crc_t *out)
{
	xmlrpc_value *res;
	int i;

	out->n_words = xmlrpc_array_size(&env, xml_crc);
	for (i = 0; i < out->n_words; i++) {
		xmlrpc_array_read_item(&env, xml_crc, i, &res);
		xmlrpc_read_int(&env, res, (int*)&out->crc[i]);
		xmlrpc_DECREF(res);
	}
}

/**
 * chamelium_get_crc_for_area:
 * @id: The ID of the port from which we want to retrieve the CRC
 * @x: The X coordinate on the emulated display to start calculating the CRC
 * from
 * @y: The Y coordinate on the emulated display to start calculating the CRC
 * from
 * @w: The width of the area to fetch the CRC from, or %0 for the whole display
 * @h: The height of the area to fetch the CRC from, or %0 for the whole display
 *
 * Reads back the pixel CRC for an area on the specified chamelium port. This
 * is the same as using the CRC readback from a GPU, the main difference being
 * the data is provided by the chamelium and also allows us to specify a region
 * of the screen to use as opposed to the entire thing.
 *
 * Returns: The CRC read back from the chamelium
 */
igt_crc_t *chamelium_get_crc_for_area(int id, int x, int y, int w, int h)
{
	xmlrpc_value *res;
	igt_crc_t *ret = malloc(sizeof(igt_crc_t));;

	res = xmlrpc_client_call(&env, chamelium_url, "ComputePixelChecksum",
				 (w && h) ? "(iiiii)" : "(innnn)",
				 id, x, y, w, h);
	check_rpc();

	crc_from_xml(res, ret);
	xmlrpc_DECREF(res);

	return ret;
}

/**
 * chamelium_start_capture:
 * @id: The ID of the port for which we want to start capturing frames on
 * @x: The X coordinate to crop the video to
 * @y: The Y coordinate to crop the video to
 * @w: The width of the cropped video, or %0 for the whole display
 * @h: The height of the cropped video, or %0 for the whole display
 *
 * Starts capturing video frames on the given Chamelium port. Once the user is
 * finished capturing frames, they should call #chamelium_stop_capture.
 *
 * For capturing a single frame, users can use the one-shot
 * @chamelium_get_crc_for_area
 */
void chamelium_start_capture(int id, int x, int y, int w, int h)
{
	xmlrpc_client_call(&env, chamelium_url, "StartCapturingVideo",
			   (w && h) ? "(iiiii)" : "(innnn)", id, x, y, w, h);
	check_rpc();
}

/**
 * chamelium_stop_capture:
 * @frame_count: The number of frames to wait to capture, or %0 to stop
 * immediately
 *
 * Finishes capturing video frames on the given Chamelium port. If @frame_count
 * is specified, this call will block until the given number of frames have been
 * captured.
 */
void chamelium_stop_capture(int frame_count)
{
	xmlrpc_client_call(&env, chamelium_url, "StopCapturingVideo",
			   "(i)", frame_count);
	check_rpc();
}

/**
 * chamelium_read_captured_crcs:
 * @frame_count: Where to store the number of CRCs we read in
 *
 * Reads all of the CRCs that have been captured thus far from the Chamelium.
 *
 * Returns: An array of @frame_count length containing all of the CRCs we read
 */
igt_crc_t *chamelium_read_captured_crcs(int *frame_count)
{
	igt_crc_t *ret;
	xmlrpc_value *res, *elem;
	int i;

	res = xmlrpc_client_call(&env, chamelium_url, "GetCapturedChecksums",
				 "(in)", 0);
	check_rpc();

	*frame_count = xmlrpc_array_size(&env, res);
	ret = calloc(sizeof(igt_crc_t), *frame_count);

	for (i = 0; i < *frame_count; i++) {
		xmlrpc_array_read_item(&env, res, i, &elem);

		crc_from_xml(elem, &ret[i]);
		ret[i].frame = i;

		xmlrpc_DECREF(elem);
	}

	xmlrpc_DECREF(res);

	return ret;
}

/**
 * chamelium_get_frame_limit:
 * @id: The ID of the port to get the capture frame limit for
 * @w: The width of the area to get the capture frame limit for, or %0 for the
 * whole display
 * @h: The height of the area to get the capture frame limit for, or %0 for the
 * whole display
 *
 * Gets the max number of frames we can capture with the Chamelium for the given
 * resolution.
 *
 * Returns: The number of the max number of frames we can capture
 */
int chamelium_get_frame_limit(int id, int w, int h)
{
	xmlrpc_value *res;
	int ret;

	if (!w && !h)
		chamelium_port_get_resolution(id, &w, &h);

	res = xmlrpc_client_call(&env, chamelium_url, "GetMaxFrameLimit",
				 "(iii)", id, w, h);
	check_rpc();

	xmlrpc_read_int(&env, res, &ret);
	xmlrpc_DECREF(res);

	return ret;
}

static unsigned int chamelium_get_port_type(int port)
{
	xmlrpc_value *res;
	const char *port_type_str;
	unsigned int port_type;

	res = xmlrpc_client_call(&env, chamelium_url, "GetConnectorType",
				 "(i)", port);
	check_rpc();

	xmlrpc_read_string(&env, res, &port_type_str);
	igt_debug("Port %d is of type '%s'\n", port, port_type_str);

	if (strcmp(port_type_str, "DP") == 0)
		port_type = DRM_MODE_CONNECTOR_DisplayPort;
	else if (strcmp(port_type_str, "HDMI") == 0)
		port_type = DRM_MODE_CONNECTOR_HDMIA;
	else if (strcmp(port_type_str, "VGA") == 0)
		port_type = DRM_MODE_CONNECTOR_VGA;
	else
		port_type = DRM_MODE_CONNECTOR_Unknown;

	free((void*)port_type_str);
	xmlrpc_DECREF(res);

	return port_type;
}

static void chamelium_read_port_mappings(int drm_fd, GKeyFile *key_file)
{
	drmModeRes *res;
	drmModeConnector *connector;
	struct chamelium_port *port;
	GError *error = NULL;
	char **group_list;
	char *group, *map_name;
	size_t group_list_len;
	int port_i, i, j;

	group_list = g_key_file_get_groups(key_file, &group_list_len);
	chamelium_port_count = group_list_len - 1;
	chamelium_ports = calloc(sizeof(struct chamelium_port),
				 chamelium_port_count);
	memset(chamelium_ports, 0,
	       sizeof(struct chamelium_port) * chamelium_port_count);
	port_i = 0;
	res = drmModeGetResources(drm_fd);

	for (i = 0; group_list[i] != NULL; i++) {
		group = group_list[i];

		if (!strstr(group, "Chamelium:"))
			continue;

		map_name = group + (sizeof("Chamelium:") - 1);

		port = &chamelium_ports[port_i++];
		port->connector_name = strdup(map_name);
		port->id = g_key_file_get_integer(key_file, group,
						  "ChameliumPortID",
						  &error);
		igt_require_f(port->id,
			      "Failed to read chamelium port ID for %s: %s\n",
			      map_name, error->message);

		port->type = chamelium_get_port_type(port->id);
		igt_require_f(port->type != DRM_MODE_CONNECTOR_Unknown,
			      "Unable to retrieve the physical port type from the Chamelium for '%s'\n",
			      map_name);

		for (j = 0;
		     j < res->count_connectors && !port->connector_id;
		     j++) {
			char connector_name[50];

			connector = drmModeGetConnectorCurrent(
			    drm_fd, res->connectors[j]);

			/* We have to generate the connector name on our own */
			snprintf(connector_name, 50, "%s-%u",
				 kmstest_connector_type_str(connector->connector_type),
				 connector->connector_type_id);

			if (strcmp(connector_name, map_name) == 0)
				port->connector_id = connector->connector_id;

			drmModeFreeConnector(connector);
		}
		igt_assert_f(port->connector_id,
			     "No connector found with name '%s'\n", map_name);

		igt_debug("Port '%s' with physical type '%s' mapped to Chamelium port %d\n",
			  map_name, kmstest_connector_type_str(port->type),
			  port->id);
	}

	drmModeFreeResources(res);
	g_strfreev(group_list);
}

static void chamelium_read_config(int drm_fd)
{
	GKeyFile *key_file = g_key_file_new();
	GError *error = NULL;
	char *key_file_loc;
	int rc;

	key_file_loc = getenv("IGT_CONFIG_PATH");
	if (!key_file_loc) {
		igt_require(key_file_loc = alloca(100));
		snprintf(key_file_loc, 100, "%s/.igtrc",
			 g_get_home_dir());
	}

	rc = g_key_file_load_from_file(key_file, key_file_loc,
				       G_KEY_FILE_NONE, &error);
	igt_require_f(rc, "Failed to read chamelium configuration file: %s\n",
		      error->message);

	chamelium_url = g_key_file_get_string(key_file, "Chamelium", "URL",
					      &error);
	igt_require_f(chamelium_url,
		      "Couldn't read chamelium URL from config file: %s\n",
		      error->message);

	chamelium_read_port_mappings(drm_fd, key_file);

	g_key_file_free(key_file);
}

/**
 * chamelium_reset:
 *
 * Resets the chamelium's IO board. As well, this also has the effect of
 * causing all of the chamelium ports to get set to unplugged
 */
void chamelium_reset(void)
{
	xmlrpc_value *res;

	igt_debug("Resetting the chamelium\n");

	res = xmlrpc_client_call(&env, chamelium_url, "Reset", "()");
	check_rpc();

	xmlrpc_DECREF(res);
}

static void chamelium_exit_handler(int sig)
{
	xmlrpc_env_clean(&env);
	xmlrpc_env_init(&env);

	chamelium_deinit();
}

/**
 * chamelium_init:
 * @drm_fd: drm file descriptor
 *
 * Sets up a connection with a chamelium, using the URL specified in the
 * Chamelium configuration. This must be called first before trying to use the
 * chamelium.
 *
 * If we fail to establish a connection with the chamelium, fail to find a
 * configured connector, etc. we fail the current test.
 */
void chamelium_init(int drm_fd)
{
	xmlrpc_env_init(&env);

	xmlrpc_client_init2(&env, XMLRPC_CLIENT_NO_FLAGS, PACKAGE,
			    PACKAGE_VERSION, NULL, 0);
	igt_fail_on_f(env.fault_occurred,
		      "Failed to init xmlrpc: %s\n",
		      env.fault_string);

	chamelium_read_config(drm_fd);
	chamelium_reset();

	igt_install_exit_handler(chamelium_exit_handler);
}

/**
 * chamelium_deinit:
 *
 * Frees the resources used by a connection to the chamelium that was set up
 * with #chamelium_init. As well, this function restores the state of the
 * chamelium like it was before calling #chamelium_init. This function is also
 * called as an exit handler, so users only need to call manually if they don't
 * want the chamelium interfering with other tests in the same file.
 */
void chamelium_deinit(void)
{
	int i;
	struct chamelium_edid *pos, *tmp;

	if (!chamelium_url)
		return;

	/* We want to make sure we leave all of the ports plugged in, since
	 * testing setups requiring multiple monitors are probably using the
	 * chamelium to provide said monitors
	 */
	chamelium_reset();
	for (i = 0; i < chamelium_port_count; i++)
		chamelium_plug(chamelium_ports[i].id);

	/* Destroy any EDIDs we created to make sure we don't leak them */
	igt_list_for_each_safe(pos, tmp, &allocated_edids->link, link) {
		chamelium_destroy_edid(pos->id);
		free(pos);
	}

	xmlrpc_client_cleanup();
	xmlrpc_env_clean(&env);

	for (i = 0; i < chamelium_port_count; i++)
		free(chamelium_ports[i].connector_name);

	free(chamelium_ports);
	allocated_edids = NULL;
	chamelium_url = NULL;
	chamelium_ports = NULL;
	chamelium_port_count = 0;
}

