/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2005 by Dominic Rath
 * Dominic.Rath@gmx.de
 *
 * Copyright (C) 2007-2010 Øyvind Harboe
 * oyvind.harboe@zylin.com
 */

#ifndef SVF_H
#define SVF_H

#include <stdint.h>

/*-----</Macros>-------------------------------------------------*/

/**
 * Defines JTAG Test Access Port states.
 *
 * These definitions were gleaned from the ARM7TDMI-S Technical
 * Reference Manual and validated against several other ARM core
 * technical manuals.
 *
 * FIXME some interfaces require specific numbers be used, as they
 * are handed-off directly to their hardware implementations.
 * Fix those drivers to map as appropriate ... then pick some
 * sane set of numbers here (where 0/uninitialized == INVALID).
 */
typedef enum tap_state {
	TAP_INVALID = -1,
	/* Proper ARM recommended numbers */
	TAP_DREXIT2 = 0x0,
	TAP_DREXIT1 = 0x1,
	TAP_DRSHIFT = 0x2,
	TAP_DRPAUSE = 0x3,
	TAP_IRSELECT = 0x4,
	TAP_DRUPDATE = 0x5,
	TAP_DRCAPTURE = 0x6,
	TAP_DRSELECT = 0x7,
	TAP_IREXIT2 = 0x8,
	TAP_IREXIT1 = 0x9,
	TAP_IRSHIFT = 0xa,
	TAP_IRPAUSE = 0xb,
	TAP_IDLE = 0xc,
	TAP_IRUPDATE = 0xd,
	TAP_IRCAPTURE = 0xe,
	TAP_RESET = 0x0f,
} tap_state_t;

/**
 * Defines arguments for reset functions
 */
#define SRST_DEASSERT   0
#define SRST_ASSERT     1
#define TRST_DEASSERT   0
#define TRST_ASSERT     1

/**
 * Function tap_state_name
 * Returns a string suitable for display representing the JTAG tap_state
 */
const char *tap_state_name(tap_state_t state);

/** Provides user-friendly name lookup of TAP states. */
tap_state_t tap_state_by_name(const char *name);

/** The current TAP state of the pending JTAG command queue. */
extern tap_state_t cmd_queue_cur_state;

/**
 * This structure defines a single scan field in the scan. It provides
 * fields for the field's width and pointers to scan input and output
 * values.
 *
 * In addition, this structure includes a value and mask that is used by
 * jtag_add_dr_scan_check() to validate the value that was scanned out.
 */
struct scan_field {
	/** The number of bits this field specifies */
	int num_bits;
	/** A pointer to value to be scanned into the device */
	const uint8_t *out_value;
	/** A pointer to a 32-bit memory location for data scanned out */
	uint8_t *in_value;

	/** The value used to check the data scanned out. */
	uint8_t *check_value;
	/** The mask to go with check_value */
	uint8_t *check_mask;
};

int handle_svf_command(char *filename);
#endif /* SVF_H */
