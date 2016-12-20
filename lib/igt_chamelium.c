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

struct chamelium_edid {
	int id;
	struct igt_list link;
};

struct chamelium_port {
	unsigned int type;
	int id;
	int connector_id;
	char *name;
};

struct chamelium_frame_data {
	int frame_count;
	size_t frame_size;
	unsigned char **frames;
};

struct chamelium {
	xmlrpc_env env;
	xmlrpc_client *client;
	char *url;

	int drm_fd;

	struct chamelium_edid *edids;
	struct chamelium_port *ports;
	int port_count;

	struct igt_list link;
};

struct chamelium *chamelium_list;

/**
 * chamelium_get_ports:
 * @chamelium: The Chamelium instance to use
 * @count: Where to store the number of ports
 *
 * Retrieves all of the ports currently configured for use with this chamelium
 *
 * Returns: an array containing a pointer to each configured chamelium port
 */
struct chamelium_port **chamelium_get_ports(struct chamelium *chamelium,
					    int *count)
{
	int i;
	struct chamelium_port **ret =
		calloc(sizeof(void*), chamelium->port_count);

	*count = chamelium->port_count;
	for (i = 0; i < chamelium->port_count; i++)
		ret[i] = &chamelium->ports[i];

	return ret;
}

/**
 * chamelium_port_get_type:
 * @chamelium: The Chamelium instance to use
 * @port: The chamelium port to retrieve the type from
 *
 * Retrieves the DRM connector type of the physical port on the Chamelium. It
 * should be noted that this type may differ from the type provided by the
 * driver.
 *
 * Returns: the DRM connector type of the physical Chamelium port
 */
unsigned int chamelium_port_get_type(const struct chamelium_port *port) {
	return port->type;
}

/**
 * chamelium_port_get_connector:
 * @chamelium: The Chamelium instance to use
 * @port: The chamelium port to retrieve the DRM connector for
 * @reprobe: Whether or not to reprobe the DRM connector
 *
 * Get a drmModeConnector object for the given Chamelium port, and optionally
 * reprobe the port in the process
 *
 * Returns: a drmModeConnector object corresponding to the given port
 */
drmModeConnector *chamelium_port_get_connector(struct chamelium *chamelium,
					       struct chamelium_port *port,
					       bool reprobe)
{
	drmModeConnector *connector;

	if (reprobe)
		connector = drmModeGetConnector(chamelium->drm_fd,
						port->connector_id);
	else
		connector = drmModeGetConnectorCurrent(chamelium->drm_fd,
						       port->connector_id);

	return connector;
}

/**
 * chamelium_port_get_name:
 * @port: The chamelium port to retrieve the name of
 *
 * Gets the name of the DRM connector corresponding to the given Chamelium
 * port.
 *
 * Returns: the name of the DRM connector
 */
const char *chamelium_port_get_name(struct chamelium_port *port)
{
	return port->name;
}

/**
 * chamelium_frame_data_get_frame_count:
 * @data: The frame data to retrieve the frame count for
 *
 * Get the number of video frames contained in a pixel dump from the Chamelium.
 *
 * Returns: number of video frames in @data
 */
int chamelium_frame_data_get_frame_count(const struct chamelium_frame_data *data)
{
	return data->frame_count;
}

/**
 * chamelium_free_frame_data:
 * @data: The frame data to free
 *
 * Frees all of the resources being used by the given frame data structure.
 * This function should be called to cleanup frame dumps from the chamelium
 * once the user is done with them.
 */
void chamelium_free_frame_data(struct chamelium_frame_data *data)
{
	int i;

	for (i = 0; i < data->frame_count; i++)
		free(data->frames[i]);

	free(data);
}

/**
 * chamelium_frame_data_get_frame:
 * @data: The frame data from the Chamelium containing the frame we want
 * @index: The index of the frame we want to retrieve
 * @len: Where to store the length of the frame
 *
 * Retrieves the raw RGB pixel data for a frame in @data. This data need not be
 * freed.
 *
 * Returns: the raw RGB pixel data for the given frame
 */
const unsigned char *chamelium_frame_data_get_frame(const struct chamelium_frame_data *data,
						    unsigned int index,
						    size_t *len)
{
	*len = data->frame_size;
	return data->frames[index];
}

static xmlrpc_value *chamelium_rpc(struct chamelium *chamelium,
				   const char *method_name,
				   const char *format_str,
				   ...)
{
	xmlrpc_value *res;
	va_list va_args;

	va_start(va_args, format_str);
	xmlrpc_client_call2f_va(&chamelium->env, chamelium->client,
				chamelium->url, method_name, format_str, &res,
				va_args);
	va_end(va_args);

	igt_assert_f(!chamelium->env.fault_occurred,
		     "Chamelium RPC call failed: %s\n",
		     chamelium->env.fault_string);

	return res;
}

/**
 * chamelium_plug:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port on the chamelium to plug
 *
 * Simulate a display connector being plugged into the system using the
 * chamelium.
 */
void chamelium_plug(struct chamelium *chamelium, struct chamelium_port *port)
{
	igt_debug("Plugging %s\n", port->name);
	xmlrpc_DECREF(chamelium_rpc(chamelium, "Plug", "(i)", port->id));
}

/**
 * chamelium_unplug:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port on the chamelium to unplug
 *
 * Simulate a display connector being unplugged from the system using the
 * chamelium.
 */
void chamelium_unplug(struct chamelium *chamelium, struct chamelium_port *port)
{
	igt_debug("Unplugging port %s\n", port->name);
	xmlrpc_DECREF(chamelium_rpc(chamelium, "Unplug", "(i)", port->id));
}

/**
 * chamelium_is_plugged:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port on the chamelium to check the status of
 *
 * Check whether or not the given port has been plugged into the system using
 * #chamelium_plug.
 *
 * Returns: %true if the connector is set to plugged in, %false otherwise.
 */
bool chamelium_is_plugged(struct chamelium *chamelium,
			  struct chamelium_port *port)
{
	xmlrpc_value *res;
	xmlrpc_bool is_plugged;

	res = chamelium_rpc(chamelium, "IsPlugged", "(i)", port->id);

	xmlrpc_read_bool(&chamelium->env, res, &is_plugged);
	xmlrpc_DECREF(res);

	return is_plugged;
}

/**
 * chamelium_port_wait_video_input_stable:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port on the chamelium to check the status of
 * @timeout_secs: How long to wait for a video signal to appear before timing
 * out
 *
 * Waits for a video signal to appear on the given port. This is useful for
 * checking whether or not we've setup a monitor correctly.
 *
 * Returns: %true if a video signal was detected, %false if we timed out
 */
bool chamelium_port_wait_video_input_stable(struct chamelium *chamelium,
					    struct chamelium_port *port,
					    int timeout_secs)
{
	xmlrpc_value *res;
	xmlrpc_bool is_on;

	igt_debug("Waiting for video input to stabalize on %s\n", port->name);

	res = chamelium_rpc(chamelium, "WaitVideoInputStable", "(ii)",
			    port->id, timeout_secs);

	xmlrpc_read_bool(&chamelium->env, res, &is_on);
	xmlrpc_DECREF(res);

	return is_on;
}

/**
 * chamelium_fire_hpd_pulses:
 * @chamelium: The Chamelium instance to use
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
void chamelium_fire_hpd_pulses(struct chamelium *chamelium,
			       struct chamelium_port *port,
			       int width_msec, int count)
{
	xmlrpc_value *pulse_widths = xmlrpc_array_new(&chamelium->env),
		     *width = xmlrpc_int_new(&chamelium->env, width_msec);
	int i;

	igt_debug("Firing %d HPD pulses with width of %d msec on %s\n",
		  count, width_msec, port->name);

	for (i = 0; i < count; i++)
		xmlrpc_array_append_item(&chamelium->env, pulse_widths, width);

	xmlrpc_DECREF(chamelium_rpc(chamelium, "FireMixedHpdPulses", "(iA)",
				    port->id, pulse_widths));

	xmlrpc_DECREF(width);
	xmlrpc_DECREF(pulse_widths);
}

/**
 * chamelium_fire_mixed_hpd_pulses:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port to fire hotplug pulses on
 * @...: The length of each pulse in milliseconds, terminated with a %0
 *
 * Does the same thing as #chamelium_fire_hpd_pulses, but allows the caller to
 * specify the length of each individual pulse.
 */
void chamelium_fire_mixed_hpd_pulses(struct chamelium *chamelium,
				     struct chamelium_port *port, ...)
{
	va_list args;
	xmlrpc_value *pulse_widths = xmlrpc_array_new(&chamelium->env),
		     *width;
	int arg;

	igt_debug("Firing mixed HPD pulses on %s\n", port->name);

	va_start(args, port);
	for (arg = va_arg(args, int); arg; arg = va_arg(args, int)) {
		width = xmlrpc_int_new(&chamelium->env, arg);
		xmlrpc_array_append_item(&chamelium->env, pulse_widths, width);
		xmlrpc_DECREF(width);
	}
	va_end(args);

	xmlrpc_DECREF(chamelium_rpc(chamelium, "FireMixedHpdPulses", "(iA)",
				    port->id, pulse_widths));

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
 * @chamelium: The Chamelium instance to use
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
void chamelium_async_hpd_pulse_start(struct chamelium *chamelium,
				     struct chamelium_port *port,
				     bool high, int delay_secs)
{
	xmlrpc_value *pulse_widths = xmlrpc_array_new(&chamelium->env), *width;

	/* TODO: Actually implement something in the chameleon server to allow
	 * for delayed actions such as hotplugs. This would work a bit better
	 * and allow us to test suspend/resume on ports without hpd like VGA
	 */

	igt_debug("Sending HPD pulse (%s) on %s with %d second delay\n",
		  high ? "high->low" : "low->high", port->name, delay_secs);

	/* If we're starting at high, make the first pulse width 0 so we keep
	 * the port connected */
	if (high) {
		width = xmlrpc_int_new(&chamelium->env, 0);
		xmlrpc_array_append_item(&chamelium->env, pulse_widths, width);
		xmlrpc_DECREF(width);
	}

	width = xmlrpc_int_new(&chamelium->env, delay_secs * 1000);
	xmlrpc_array_append_item(&chamelium->env, pulse_widths, width);
	xmlrpc_DECREF(width);

	xmlrpc_client_start_rpcf(&chamelium->env, chamelium->client,
				 chamelium->url,
				 "FireMixedHpdPulses", async_rpc_handler, NULL,
				 "(iA)", port->id, pulse_widths);
	xmlrpc_DECREF(pulse_widths);
}

/**
 * chamelium_async_hpd_pulse_finish:
 * @chamelium: The Chamelium instance to use
 *
 * Waits for any asynchronous RPC started by #chamelium_async_hpd_pulse_start
 * to complete, and then cleans up any leftover responses from the chamelium.
 * If all of the RPC calls have already completed, this function returns
 * immediately.
 */
void chamelium_async_hpd_pulse_finish(struct chamelium *chamelium)
{
	xmlrpc_client_event_loop_finish(chamelium->client);
}

/**
 * chamelium_new_edid:
 * @chamelium: The Chamelium instance to use
 * @edid: The edid blob to upload to the chamelium
 *
 * Uploads and registers a new EDID with the chamelium. The EDID will be
 * destroyed automatically when #chamelium_deinit is called.
 *
 * Returns: The ID of the EDID uploaded to the chamelium.
 */
int chamelium_new_edid(struct chamelium *chamelium, const unsigned char *edid)
{
	xmlrpc_value *res;
	struct chamelium_edid *allocated_edid;
	int edid_id;

	res = chamelium_rpc(chamelium, "CreateEdid", "(6)", edid, EDID_LENGTH);

	xmlrpc_read_int(&chamelium->env, res, &edid_id);
	xmlrpc_DECREF(res);

	allocated_edid = malloc(sizeof(struct chamelium_edid));
	igt_assert(allocated_edid);

	allocated_edid->id = edid_id;
	igt_list_init(&allocated_edid->link);

	if (chamelium->edids) {
		igt_list_add(&chamelium->edids->link, &allocated_edid->link);
	} else {
		chamelium->edids = allocated_edid;
	}

	return edid_id;
}

static void chamelium_destroy_edid(struct chamelium *chamelium, int edid_id)
{
	xmlrpc_DECREF(chamelium_rpc(chamelium, "DestroyEdid", "(i)", edid_id));
}

/**
 * chamelium_port_set_edid:
 * @chamelium: The Chamelium instance to use
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
void chamelium_port_set_edid(struct chamelium *chamelium,
			     struct chamelium_port *port, int edid_id)
{
	xmlrpc_DECREF(chamelium_rpc(chamelium, "ApplyEdid", "(ii)",
				    port->id, edid_id));
}

/**
 * chamelium_port_set_ddc_state:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port whose DDC bus we want to modify
 * @enabled: Whether or not to enable the DDC bus
 *
 * This disables the DDC bus (e.g. the i2c line on the connector that gives us
 * an EDID) of the specified port on the chamelium. This is useful for testing
 * behavior on legacy connectors such as VGA, where the presence of a DDC bus
 * is not always guaranteed.
 */
void chamelium_port_set_ddc_state(struct chamelium *chamelium,
				  struct chamelium_port *port,
				  bool enabled)
{
	igt_debug("%sabling DDC bus on %s\n",
		  enabled ? "En" : "Dis", port->name);

	xmlrpc_DECREF(chamelium_rpc(chamelium, "SetDdcState", "(ib)",
				    port->id, enabled));
}

/**
 * chamelium_port_get_ddc_state:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port whose DDC bus we want to check the status of
 *
 * Check whether or not the DDC bus on the specified chamelium port is enabled
 * or not.
 *
 * Returns: %true if the DDC bus is enabled, %false otherwise.
 */
bool chamelium_port_get_ddc_state(struct chamelium *chamelium,
				  struct chamelium_port *port)
{
	xmlrpc_value *res;
	xmlrpc_bool enabled;

	res = chamelium_rpc(chamelium, "IsDdcEnabled", "(i)", port->id);
	xmlrpc_read_bool(&chamelium->env, res, &enabled);

	xmlrpc_DECREF(res);
	return enabled;
}

/**
 * chamelium_port_get_resolution:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port whose display resolution we want to check
 * @x: Where to store the horizontal resolution of the port
 * @y: Where to store the verical resolution of the port
 *
 * Check the current reported display resolution of the specified port on the
 * chamelium. This information is provided by the chamelium itself, not DRM.
 * Useful for verifying that we really are scanning out at the resolution we
 * think we are.
 */
void chamelium_port_get_resolution(struct chamelium *chamelium,
				   struct chamelium_port *port,
				   int *x, int *y)
{
	xmlrpc_value *res, *res_x, *res_y;

	res = chamelium_rpc(chamelium, "DetectResolution", "(i)", port->id);

	xmlrpc_array_read_item(&chamelium->env, res, 0, &res_x);
	xmlrpc_array_read_item(&chamelium->env, res, 1, &res_y);
	xmlrpc_read_int(&chamelium->env, res_x, x);
	xmlrpc_read_int(&chamelium->env, res_y, y);

	xmlrpc_DECREF(res_x);
	xmlrpc_DECREF(res_y);
	xmlrpc_DECREF(res);
}

/**
 * chamelium_port_dump_pixels:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port we want to dump pixels from
 * @x: The X coordinate to crop the screen capture to
 * @y: The Y coordinate to crop the screen capture to
 * @w: The width of the area to crop the screen capture to, or 0 for the whole
 * screen
 * @h: The height of the area to crop the screen capture to, or 0 for the whole
 * screen
 * @len: Where to store the len of the pixel dump
 *
 * Captures the currently displayed image on the given chamelium port,
 * optionally cropped to a given region. In situations where pre-calculating
 * CRCs may not be reliable, this can be used as an alternative for figuring
 * out whether or not the correct images are being displayed on the screen.
 *
 * The RGB data returned by this function should be freed when it is no longer
 * needed.
 *
 * Returns: a pointer to an RGB dump of the current screen contents
 */
unsigned char *chamelium_port_dump_pixels(struct chamelium *chamelium,
					  struct chamelium_port *port,
					  int x, int y,
					  int w, int h,
					  size_t *len)
{
	xmlrpc_value *res;
	unsigned char *ret;

	res = chamelium_rpc(chamelium, "DumpPixels",
			    (w && h) ? "(iiiii)" : "(innnn)", port->id,
			    x, y, w, h);

	xmlrpc_read_base64(&chamelium->env, res, len, (void*)&ret);
	xmlrpc_DECREF(res);

	return ret;
}

static void crc_from_xml(struct chamelium *chamelium,
			 xmlrpc_value *xml_crc, igt_crc_t *out)
{
	xmlrpc_value *res;
	int i;

	out->n_words = xmlrpc_array_size(&chamelium->env, xml_crc);
	for (i = 0; i < out->n_words; i++) {
		xmlrpc_array_read_item(&chamelium->env, xml_crc, i, &res);
		xmlrpc_read_int(&chamelium->env, res, (int*)&out->crc[i]);
		xmlrpc_DECREF(res);
	}
}

/**
 * chamelium_get_crc_for_area:
 * @chamelium: The Chamelium instance to use
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
igt_crc_t *chamelium_get_crc_for_area(struct chamelium *chamelium,
				      struct chamelium_port *port,
				      int x, int y, int w, int h)
{
	xmlrpc_value *res;
	igt_crc_t *ret = malloc(sizeof(igt_crc_t));;

	res = chamelium_rpc(chamelium, "ComputePixelChecksum",
			    (w && h) ? "(iiiii)" : "(innnn)",
			    port->id, x, y, w, h);

	crc_from_xml(chamelium, res, ret);
	xmlrpc_DECREF(res);

	return ret;
}

/**
 * chamelium_start_capture:
 * @chamelium: The Chamelium instance to use
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
void chamelium_start_capture(struct chamelium *chamelium,
			     struct chamelium_port *port, int x, int y, int w, int h)
{
	xmlrpc_DECREF(chamelium_rpc(chamelium, "StartCapturingVideo",
				    (w && h) ? "(iiiii)" : "(innnn)",
				    port->id, x, y, w, h));
}

/**
 * chamelium_stop_capture:
 * @chamelium: The Chamelium instance to use
 * @frame_count: The number of frames to wait to capture, or %0 to stop
 * immediately
 *
 * Finishes capturing video frames on the given Chamelium port. If @frame_count
 * is specified, this call will block until the given number of frames have been
 * captured.
 */
void chamelium_stop_capture(struct chamelium *chamelium, int frame_count)
{
	xmlrpc_DECREF(chamelium_rpc(chamelium, "StopCapturingVideo", "(i)",
				    frame_count));
}

/**
 * chamelium_capture:
 * @chamelium: The Chamelium instance to use
 * @id: The ID of the port for which we want to start capturing frames on
 * @x: The X coordinate to crop the video to
 * @y: The Y coordinate to crop the video to
 * @w: The width of the cropped video, or %0 for the whole display
 * @h: The height of the cropped video, or %0 for the whole display
 * @frame_count: The number of frames to capture
 *
 * Captures the given number of frames on the chamelium. This is equivalent to
 * calling #chamelium_start_capture immediately followed by
 * #chamelium_stop_capture. The caller is blocked until all of the frames have
 * been captured.
 */
void chamelium_capture(struct chamelium *chamelium, struct chamelium_port *port,
		       int x, int y, int w, int h, int frame_count)
{
	xmlrpc_DECREF(chamelium_rpc(chamelium, "CaptureVideo",
				    (w && h) ? "(iiiiii)" : "(iinnnn)",
				    port->id, frame_count, x, y, w, h));
}

/**
 * chamelium_read_captured_crcs:
 * @chamelium: The Chamelium instance to use
 * @frame_count: Where to store the number of CRCs we read in
 *
 * Reads all of the CRCs that have been captured thus far from the Chamelium.
 *
 * Returns: An array of @frame_count length containing all of the CRCs we read
 */
igt_crc_t *chamelium_read_captured_crcs(struct chamelium *chamelium,
					int *frame_count)
{
	igt_crc_t *ret;
	xmlrpc_value *res, *elem;
	int i;

	res = chamelium_rpc(chamelium, "GetCapturedChecksums", "(in)", 0);

	*frame_count = xmlrpc_array_size(&chamelium->env, res);
	ret = calloc(sizeof(igt_crc_t), *frame_count);

	for (i = 0; i < *frame_count; i++) {
		xmlrpc_array_read_item(&chamelium->env, res, i, &elem);

		crc_from_xml(chamelium, elem, &ret[i]);
		ret[i].frame = i;

		xmlrpc_DECREF(elem);
	}

	xmlrpc_DECREF(res);

	return ret;
}

/**
 * chamelium_port_read_captured_frame:
 *
 * @chamelium: The Chamelium instance to use
 * @index: The index of the captured frame we want to get
 * @len: How large the raw pixel dump is
 *
 * Retrieves a single video frame captured during the last video capture on the
 * Chamelium. This data should be freed once the caller is done with it.
 *
 * The pixel data returned is in RGB888.
 *
 * Returns: the RGB pixel dump of the captured frame
 */
unsigned char *chamelium_read_captured_frame(struct chamelium *chamelium,
					     unsigned int index,
					     size_t *len)
{
	xmlrpc_value *res;
	unsigned char *ret;

	res = chamelium_rpc(chamelium, "ReadCapturedFrame", "(i)", index);

	xmlrpc_read_base64(&chamelium->env, res, len, (void*)&ret);
	xmlrpc_DECREF(res);

	return ret;
}

/**
 * chamelium_get_captured_frame_count:
 * @chamelium: The Chamelium instance to use
 *
 * Gets the number of frames that were captured during the last video capture.
 *
 * Returns: the number of frames the Chamelium captured during the last video
 * capture.
 */
int chamelium_get_captured_frame_count(struct chamelium *chamelium)
{
	xmlrpc_value *res;
	int ret;

	res = chamelium_rpc(chamelium, "GetCapturedFrameCount", "()");
	xmlrpc_read_int(&chamelium->env, res, &ret);

	xmlrpc_DECREF(res);
	return ret;
}

/**
 * chamelium_get_frame_limit:
 * @chamelium: The Chamelium instance to use
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
int chamelium_get_frame_limit(struct chamelium *chamelium, struct chamelium_port *port,
			      int w, int h)
{
	xmlrpc_value *res;
	int ret;

	if (!w && !h)
		chamelium_port_get_resolution(chamelium, port, &w, &h);

	res = chamelium_rpc(chamelium, "GetMaxFrameLimit", "(iii)",
			    port->id, w, h);

	xmlrpc_read_int(&chamelium->env, res, &ret);
	xmlrpc_DECREF(res);

	return ret;
}

static unsigned int chamelium_get_port_type(struct chamelium *chamelium,
					    struct chamelium_port *port)
{
	xmlrpc_value *res;
	const char *port_type_str;
	unsigned int port_type;

	res = chamelium_rpc(chamelium, "GetConnectorType", "(i)", port->id);

	xmlrpc_read_string(&chamelium->env, res, &port_type_str);
	igt_debug("Port %d is of type '%s'\n", port->id, port_type_str);

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

static void chamelium_read_port_mappings(struct chamelium *chamelium,
					 int drm_fd, GKeyFile *key_file)
{
	drmModeRes *res;
	drmModeConnector *connector;
	struct chamelium_port *port;
	GError *error = NULL;
	char **group_list;
	char *group, *map_name;
	int port_i, i, j;

	group_list = g_key_file_get_groups(key_file, NULL);

	/* Count how many connector mappings are specified in the config */
	for (i = 0; group_list[i] != NULL; i++) {
		if (strstr(group_list[i], "Chamelium:"))
			chamelium->port_count++;
	}

	chamelium->ports = calloc(sizeof(struct chamelium_port),
				  chamelium->port_count);
	memset(chamelium->ports, 0,
	       sizeof(struct chamelium_port) * chamelium->port_count);
	port_i = 0;
	res = drmModeGetResources(drm_fd);

	for (i = 0; group_list[i] != NULL; i++) {
		group = group_list[i];

		if (!strstr(group, "Chamelium:"))
			continue;

		map_name = group + (sizeof("Chamelium:") - 1);

		port = &chamelium->ports[port_i++];
		port->name = strdup(map_name);
		port->id = g_key_file_get_integer(key_file, group,
						  "ChameliumPortID",
						  &error);
		igt_require_f(port->id,
			      "Failed to read chamelium port ID for %s: %s\n",
			      map_name, error->message);

		port->type = chamelium_get_port_type(chamelium, port);
		igt_require_f(port->type != DRM_MODE_CONNECTOR_Unknown,
			      "Unable to retrieve the physical port type from the Chamelium for '%s'\n",
			      map_name);

		for (j = 0;
		     j < res->count_connectors && !port->connector_id;
		     j++) {
			char name[50];

			connector = drmModeGetConnectorCurrent(
			    drm_fd, res->connectors[j]);

			/* We have to generate the connector name on our own */
			snprintf(name, 50, "%s-%u",
				 kmstest_connector_type_str(connector->connector_type),
				 connector->connector_type_id);

			if (strcmp(name, map_name) == 0)
				port->connector_id = connector->connector_id;

			drmModeFreeConnector(connector);
		}
		igt_assert_f(port->connector_id,
			     "No connector found with name '%s'\n", map_name);

		igt_debug("Port '%s' with physical type '%s' mapped to Chamelium port %s\n",
			  map_name, kmstest_connector_type_str(port->type),
			  port->name);
	}

	drmModeFreeResources(res);
	g_strfreev(group_list);
}

static void chamelium_read_config(struct chamelium *chamelium, int drm_fd)
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

	chamelium->url = g_key_file_get_string(key_file, "Chamelium", "URL",
					       &error);
	igt_require_f(chamelium->url,
		      "Couldn't read chamelium URL from config file: %s\n",
		      error->message);

	chamelium_read_port_mappings(chamelium, drm_fd, key_file);

	g_key_file_free(key_file);
}

/**
 * chamelium_reset:
 * @chamelium: The Chamelium instance to use
 *
 * Resets the chamelium's IO board. As well, this also has the effect of
 * causing all of the chamelium ports to get set to unplugged
 */
void chamelium_reset(struct chamelium *chamelium)
{
	igt_debug("Resetting the chamelium\n");
	xmlrpc_DECREF(chamelium_rpc(chamelium, "Reset", "()"));
}

static void chamelium_exit_handler(int sig)
{
	xmlrpc_env env;
	struct chamelium *chamelium, *tmp;

	xmlrpc_env_init(&env);

	igt_list_for_each_safe(chamelium, tmp, &chamelium_list->link, link)
		chamelium_deinit(chamelium);
}

/**
 * chamelium_init:
 * @chamelium: The Chamelium instance to use
 * @drm_fd: drm file descriptor
 *
 * Sets up a connection with a chamelium, using the URL specified in the
 * Chamelium configuration. This must be called first before trying to use the
 * chamelium.
 *
 * If we fail to establish a connection with the chamelium, fail to find a
 * configured connector, etc. we fail the current test.
 *
 * Returns: A newly initialized chamelium struct, or NULL on error
 */
struct chamelium *chamelium_init(int drm_fd)
{
	struct chamelium *chamelium = malloc(sizeof(struct chamelium));

	if (!chamelium)
		return NULL;

	memset(chamelium, 0, sizeof(*chamelium));
	chamelium->drm_fd = drm_fd;
	igt_list_init(&chamelium->link);

	/* Setup the libxmlrpc context */
	xmlrpc_env_init(&chamelium->env);
	xmlrpc_client_setup_global_const(&chamelium->env);
	xmlrpc_client_create(&chamelium->env, XMLRPC_CLIENT_NO_FLAGS, PACKAGE,
			     PACKAGE_VERSION, NULL, 0, &chamelium->client);
	if (chamelium->env.fault_occurred) {
		igt_debug("Failed to init xmlrpc: %s\n",
			  chamelium->env.fault_string);
		goto error;
	}

	chamelium_read_config(chamelium, drm_fd);
	chamelium_reset(chamelium);

	igt_install_exit_handler(chamelium_exit_handler);

	if (!chamelium_list)
		chamelium_list = chamelium;
	else
		igt_list_add(&chamelium->link, &chamelium_list->link);

	return chamelium;

error:
	xmlrpc_env_clean(&chamelium->env);
	free(chamelium);

	return NULL;
}

/**
 * chamelium_deinit:
 * @chamelium: The Chamelium instance to use
 *
 * Frees the resources used by a connection to the chamelium that was set up
 * with #chamelium_init. As well, this function restores the state of the
 * chamelium like it was before calling #chamelium_init. This function is also
 * called as an exit handler, so users only need to call manually if they don't
 * want the chamelium interfering with other tests in the same file.
 */
void chamelium_deinit(struct chamelium *chamelium)
{
	int i;
	struct chamelium_edid *pos, *tmp;

	/* We want to make sure we leave all of the ports plugged in, since
	 * testing setups requiring multiple monitors are probably using the
	 * chamelium to provide said monitors
	 */
	chamelium_reset(chamelium);
	for (i = 0; i < chamelium->port_count; i++)
		chamelium_plug(chamelium, &chamelium->ports[i]);

	/* Destroy any EDIDs we created to make sure we don't leak them */
	igt_list_for_each_safe(pos, tmp, &chamelium->edids->link, link) {
		chamelium_destroy_edid(chamelium, pos->id);
		free(pos);
	}

	xmlrpc_client_destroy(chamelium->client);
	xmlrpc_env_clean(&chamelium->env);

	for (i = 0; i < chamelium->port_count; i++)
		free(chamelium->ports[i].name);

	free(chamelium->ports);
	free(chamelium);
}
