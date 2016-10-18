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
 * Authors: Lyude Paul <lyude@redhat.com>
 */

#ifndef IGT_CHAMELIUM_H
#define IGT_CHAMELIUM_H

#include "config.h"
#include "igt.h"
#include <stdbool.h>

/**
 * chamelium_port:
 * @type: The DRM connector type of the chamelium port (not the host's)
 * @id: The ID of the chamelium port
 * @connector_id: The ID of the DRM connector connected to this port
 * @connector_name: The name of the DRM connector
 */
struct chamelium_port {
	unsigned int type;
	int id;
	int connector_id;
	char *connector_name;
};

extern int chamelium_port_count;
extern struct chamelium_port *chamelium_ports;

void chamelium_init(int drm_fd);
void chamelium_deinit(void);
void chamelium_reset(void);

void chamelium_plug(int id);
void chamelium_unplug(int id);
bool chamelium_is_plugged(int id);
bool chamelium_port_wait_video_input_stable(int id, int timeout_secs);
void chamelium_fire_mixed_hpd_pulses(int id, ...);
void chamelium_fire_hpd_pulses(int id, int width_msec, int count);
void chamelium_async_hpd_pulse_start(int id, bool high, int delay_secs);
void chamelium_async_hpd_pulse_finish(void);
int chamelium_new_edid(const unsigned char *edid);
void chamelium_port_set_edid(int id, int edid_id);
bool chamelium_port_get_ddc_state(int id);
void chamelium_port_set_ddc_state(int id, bool enabled);
void chamelium_port_get_resolution(int id, int *x, int *y);
igt_crc_t *chamelium_get_crc_for_area(int id, int x, int y, int w, int h);
void chamelium_start_capture(int id, int x, int y, int w, int h);
void chamelium_stop_capture(int frame_count);
igt_crc_t *chamelium_read_captured_crcs(int *frame_count);
int chamelium_get_frame_limit(int id, int w, int h);

#endif /* IGT_CHAMELIUM_H */
