/***************************************************************************
 *    Copyright (C) 2009 by Simon Qian                                     *
 *    SimonQian@SimonQian.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

/* The specification for SVF is available here:
 * http://www.asset-intertech.com/support/svf.pdf
 * Below, this document is refered to as the "SVF spec".
 *
 * The specification for XSVF is available here:
 * http://www.xilinx.com/support/documentation/application_notes/xapp503.pdf
 * Below, this document is refered to as the "XSVF spec".
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include "svf.h"
#include "ast-jtag.h"

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define ERROR_OK                        (0)
#define ERROR_NO_CONFIG_FILE            (-2)
#define ERROR_BUF_TOO_SMALL             (-3)
#define ERROR_FAIL                      (-4)
#define ERROR_WAIT                      (-5)
#define ERROR_TIMEOUT_REACHED           (-6)

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define LOG_ERROR(x...) DBG_log(LOG_ERROR, x)
#define LOG_INFO(x...) DBG_log(LOG_INFO, x)
#define LOG_DEBUG(x...) DBG_log(LOG_DEBUG, x)
#define log_printf_lf(dbg_lvl, file, line, function, fmt, ...) \
        DBG_log(dbg_lvl, fmt)
extern int loglevel;
static int step;
static unsigned int frequency;
static int jtag_dev;

unsigned char tap_mapping[] = {
    [TAP_DREXIT2] = JTAG_UNSUPPORT,
    [TAP_DREXIT1] = JTAG_UNSUPPORT,
    [TAP_DRSHIFT] = JTAG_SHIFTDR,
    [TAP_DRPAUSE] = JTAG_PAUSEDR,
    [TAP_IRSELECT] = JTAG_UNSUPPORT,
    [TAP_DRUPDATE] = JTAG_UNSUPPORT,
    [TAP_DRCAPTURE] = JTAG_UNSUPPORT,
    [TAP_DRSELECT] = JTAG_UNSUPPORT,
    [TAP_IREXIT2] = JTAG_UNSUPPORT,
    [TAP_IREXIT1] = JTAG_UNSUPPORT,
    [TAP_IRSHIFT] = JTAG_SHIFTIR,
    [TAP_IRPAUSE] = JTAG_PAUSEIR,
    [TAP_IDLE] = JTAG_IDLE,
    [TAP_IRUPDATE] = JTAG_UNSUPPORT,
    [TAP_IRCAPTURE] = JTAG_UNSUPPORT,
    [TAP_RESET] = JTAG_TLRESET
};

void DBG_log(int level, const char *format, ...)
{
	if (level < loglevel)
		return;

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
}

static const struct name_mapping {
    enum tap_state symbol;
    const char *name;
} tap_name_mapping[] = {
    { TAP_RESET, "RESET", },
    { TAP_IDLE, "RUN/IDLE", },
    { TAP_DRSELECT, "DRSELECT", },
    { TAP_DRCAPTURE, "DRCAPTURE", },
    { TAP_DRSHIFT, "DRSHIFT", },
    { TAP_DREXIT1, "DREXIT1", },
    { TAP_DRPAUSE, "DRPAUSE", },
    { TAP_DREXIT2, "DREXIT2", },
    { TAP_DRUPDATE, "DRUPDATE", },
    { TAP_IRSELECT, "IRSELECT", },
    { TAP_IRCAPTURE, "IRCAPTURE", },
    { TAP_IRSHIFT, "IRSHIFT", },
    { TAP_IREXIT1, "IREXIT1", },
    { TAP_IRPAUSE, "IRPAUSE", },
    { TAP_IREXIT2, "IREXIT2", },
    { TAP_IRUPDATE, "IRUPDATE", },

    /* only for input:  accept standard SVF name */
    { TAP_IDLE, "IDLE", },
};

const char *tap_state_name(tap_state_t state)
{
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(tap_name_mapping); i++) {
        if (tap_name_mapping[i].symbol == state)
            return tap_name_mapping[i].name;
    }
    return "???";
}

tap_state_t tap_state_by_name(const char *name)
{
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(tap_name_mapping); i++) {
        /* be nice to the human */
        if (strcasecmp(name, tap_name_mapping[i].name) == 0)
            return tap_name_mapping[i].symbol;
    }
    /* not found */
    return TAP_INVALID;
}

/* SVF command */
enum svf_command {
	ENDDR,
	ENDIR,
	FREQUENCY,
	HDR,
	HIR,
	PIO,
	PIOMAP,
	RUNTEST,
	SDR,
	SIR,
	STATE,
	TDR,
	TIR,
	TRST,
	LOOP,
	ENDLOOP
};

static const char *svf_command_name[] = {
	"ENDDR",
	"ENDIR",
	"FREQUENCY",
	"HDR",
	"HIR",
	"PIO",
	"PIOMAP",
	"RUNTEST",
	"SDR",
	"SIR",
	"STATE",
	"TDR",
	"TIR",
	"TRST",
	"LOOP",
	"ENDLOOP"
};

enum trst_mode {
	TRST_ON,
	TRST_OFF,
	TRST_Z,
	TRST_ABSENT
};

static const char *svf_trst_mode_name[4] = {
	"ON",
	"OFF",
	"Z",
	"ABSENT"
};

struct svf_statemove {
	tap_state_t from;
	tap_state_t to;
	uint32_t num_of_moves;
	tap_state_t paths[8];
};

/*
 * These paths are from the SVF specification for the STATE command, to be
 * used when the STATE command only includes the final state.  The first
 * element of the path is the "from" (current) state, and the last one is
 * the "to" (target) state.
 *
 * All specified paths are the shortest ones in the JTAG spec, and are thus
 * not (!!) exact matches for the paths used elsewhere in OpenOCD.  Note
 * that PAUSE-to-PAUSE transitions all go through UPDATE and then CAPTURE,
 * which has specific effects on the various registers; they are not NOPs.
 *
 * Paths to RESET are disabled here.  As elsewhere in OpenOCD, and in XSVF
 * and many SVF implementations, we don't want to risk missing that state.
 * To get to RESET, always we ignore the current state.
 */
static const struct svf_statemove svf_statemoves[] = {
	/* from			to				num_of_moves,	paths[8] */
/*	{TAP_RESET,		TAP_RESET,		1,				{TAP_RESET}}, */
	{TAP_RESET,		TAP_IDLE,		2,				{TAP_RESET, TAP_IDLE} },
	{TAP_RESET,		TAP_DRPAUSE,	6,				{TAP_RESET, TAP_IDLE, TAP_DRSELECT,
														TAP_DRCAPTURE, TAP_DREXIT1, TAP_DRPAUSE} },
	{TAP_RESET,		TAP_IRPAUSE,	7,				{TAP_RESET, TAP_IDLE, TAP_DRSELECT,
														TAP_IRSELECT, TAP_IRCAPTURE,
														TAP_IREXIT1, TAP_IRPAUSE} },

/*	{TAP_IDLE,		TAP_RESET,		4,				{TAP_IDLE,
 * TAP_DRSELECT, TAP_IRSELECT, TAP_RESET}}, */
	{TAP_IDLE,		TAP_IDLE,		1,				{TAP_IDLE} },
	{TAP_IDLE,		TAP_DRPAUSE,	5,				{TAP_IDLE, TAP_DRSELECT, TAP_DRCAPTURE,
														TAP_DREXIT1, TAP_DRPAUSE} },
	{TAP_IDLE,		TAP_IRPAUSE,	6,				{TAP_IDLE, TAP_DRSELECT, TAP_IRSELECT,
														TAP_IRCAPTURE, TAP_IREXIT1, TAP_IRPAUSE} },

/*	{TAP_DRPAUSE,	TAP_RESET,		6,				{TAP_DRPAUSE,
 * TAP_DREXIT2, TAP_DRUPDATE, TAP_DRSELECT, TAP_IRSELECT, TAP_RESET}}, */
	{TAP_DRPAUSE,	TAP_IDLE,		4,				{TAP_DRPAUSE, TAP_DREXIT2, TAP_DRUPDATE,
														TAP_IDLE} },
	{TAP_DRPAUSE,	TAP_DRPAUSE,	7,				{TAP_DRPAUSE, TAP_DREXIT2, TAP_DRUPDATE,
														TAP_DRSELECT, TAP_DRCAPTURE,
														TAP_DREXIT1, TAP_DRPAUSE} },
	{TAP_DRPAUSE,	TAP_IRPAUSE,	8,				{TAP_DRPAUSE, TAP_DREXIT2, TAP_DRUPDATE,
														TAP_DRSELECT, TAP_IRSELECT,
														TAP_IRCAPTURE, TAP_IREXIT1, TAP_IRPAUSE} },

/*	{TAP_IRPAUSE,	TAP_RESET,		6,				{TAP_IRPAUSE,
 * TAP_IREXIT2, TAP_IRUPDATE, TAP_DRSELECT, TAP_IRSELECT, TAP_RESET}}, */
	{TAP_IRPAUSE,	TAP_IDLE,		4,				{TAP_IRPAUSE, TAP_IREXIT2, TAP_IRUPDATE,
														TAP_IDLE} },
	{TAP_IRPAUSE,	TAP_DRPAUSE,	7,				{TAP_IRPAUSE, TAP_IREXIT2, TAP_IRUPDATE,
														TAP_DRSELECT, TAP_DRCAPTURE,
														TAP_DREXIT1, TAP_DRPAUSE} },
	{TAP_IRPAUSE,	TAP_IRPAUSE,	8,				{TAP_IRPAUSE, TAP_IREXIT2, TAP_IRUPDATE,
														TAP_DRSELECT, TAP_IRSELECT,
														TAP_IRCAPTURE, TAP_IREXIT1, TAP_IRPAUSE} }
};

#define XXR_TDI				(1 << 0)
#define XXR_TDO				(1 << 1)
#define XXR_MASK			(1 << 2)
#define XXR_SMASK			(1 << 3)
struct svf_xxr_para {
	int len;
	int data_mask;
	uint8_t *tdi;
	uint8_t *tdo;
	uint8_t *mask;
	uint8_t *smask;
};

struct svf_para {
	float frequency;
	tap_state_t ir_end_state;
	tap_state_t dr_end_state;
	tap_state_t runtest_run_state;
	tap_state_t runtest_end_state;
	enum trst_mode trst_mode;

	struct svf_xxr_para hir_para;
	struct svf_xxr_para hdr_para;
	struct svf_xxr_para tir_para;
	struct svf_xxr_para tdr_para;
	struct svf_xxr_para sir_para;
	struct svf_xxr_para sdr_para;
};

static struct svf_para svf_para;
static const struct svf_para svf_para_init = {
/*	frequency, ir_end_state, dr_end_state, runtest_run_state, runtest_end_state, trst_mode */
	0,			TAP_IDLE,		TAP_IDLE,	TAP_IDLE,		TAP_IDLE,		TRST_Z,
/*	hir_para */
/*	{len,	data_mask,	tdi,	tdo,	mask,	smask}, */
	{0,			0,		NULL,	NULL,	NULL,	NULL},
/*	hdr_para */
/*	{len,	data_mask,	tdi,	tdo,	mask,	smask}, */
	{0,			0,		NULL,	NULL,	NULL,	NULL},
/*	tir_para */
/*	{len,	data_mask,	tdi,	tdo,	mask,	smask}, */
	{0,			0,		NULL,	NULL,	NULL,	NULL},
/*	tdr_para */
/*	{len,	data_mask,	tdi,	tdo,	mask,	smask}, */
	{0,			0,		NULL,	NULL,	NULL,	NULL},
/*	sir_para */
/*	{len,	data_mask,	tdi,	tdo,	mask,	smask}, */
	{0,			0,		NULL,	NULL,	NULL,	NULL},
/*	sdr_para */
/*	{len,	data_mask,	tdi,	tdo,	mask,	smask}, */
	{0,			0,		NULL,	NULL,	NULL,	NULL},
};

struct svf_check_tdo_para {
	int line_num;		/* used to record line number of the check operation */
	/* so more information could be printed */
	int enabled;		/* check is enabled or not */
	int buffer_offset;	/* buffer_offset to buffers */
	int bit_len;		/* bit length to check */
};

#define SVF_CHECK_TDO_PARA_SIZE 1024
static struct svf_check_tdo_para *svf_check_tdo_para;
static int svf_check_tdo_para_index;

static int svf_read_command_from_file(FILE *fd);
static int svf_check_tdo(void);
static int svf_add_check_para(uint8_t enabled, int buffer_offset, int bit_len);
static int svf_run_command(char *cmd_str);

static FILE *svf_fd;
static char *svf_read_line;
static size_t svf_read_line_size;
static char *svf_command_buffer;
static size_t svf_command_buffer_size;
static int svf_line_number;
static int svf_getline(char **lineptr, size_t *n, FILE *stream);
long file_offset;
int loop;

#define SVF_MAX_BUFFER_SIZE_TO_COMMIT   (1024 * 1024)
static uint8_t *svf_tdi_buffer, *svf_tdo_buffer, *svf_mask_buffer;
static int svf_buffer_index, svf_buffer_size ;
static int svf_quiet;
static int svf_nil;
static int svf_ignore_error;

/* Targetting particular tap */
static int svf_tap_is_specified;
static int svf_set_padding(struct svf_xxr_para *para, int len, unsigned char tdi);

/* Progress Indicator */
static long svf_total_lines;
static int svf_percentage;
static int svf_last_printed_percentage = -1;

/* helper/binbarybuffer.c */
void *buf_cpy(const void *from, void *_to, unsigned size)
{
	if (NULL == from || NULL == _to)
		return NULL;

	/* copy entire buffer */
	memcpy(_to, from, DIV_ROUND_UP(size, 8));

	/* mask out bits that don't belong to the buffer */
	unsigned trailing_bits = size % 8;
	if (trailing_bits) {
		uint8_t *to = _to;
		to[size / 8] &= (1 << trailing_bits) - 1;
	}
	return _to;
}

static bool buf_cmp_masked(uint8_t a, uint8_t b, uint8_t m)
{
	return (a & m) != (b & m);
}

static bool buf_cmp_trailing(uint8_t a, uint8_t b, uint8_t m, unsigned trailing)
{
	uint8_t mask = (1 << trailing) - 1;
	return buf_cmp_masked(a, b, mask & m);
}

bool buf_cmp(const void *_buf1, const void *_buf2, unsigned size)
{
	if (!_buf1 || !_buf2)
		return _buf1 != _buf2;

	unsigned last = size / 8;
	if (memcmp(_buf1, _buf2, last) != 0)
		return false;

	unsigned trailing = size % 8;
	if (!trailing)
		return false;

	const uint8_t *buf1 = _buf1, *buf2 = _buf2;
	return buf_cmp_trailing(buf1[last], buf2[last], 0xff, trailing);
}

bool buf_cmp_mask(const void *_buf1, const void *_buf2,
	const void *_mask, unsigned size)
{
	if (!_buf1 || !_buf2)
		return _buf1 != _buf2 || _buf1 != _mask;

	const uint8_t *buf1 = _buf1, *buf2 = _buf2, *mask = _mask;
	unsigned last = size / 8;
	for (unsigned i = 0; i < last; i++) {
		if (buf_cmp_masked(buf1[i], buf2[i], mask[i]))
			return true;
	}
	unsigned trailing = size % 8;
	if (!trailing)
		return false;
	return buf_cmp_trailing(buf1[last], buf2[last], mask[last], trailing);
}

void *buf_set_ones(void *_buf, unsigned size)
{
	uint8_t *buf = _buf;
	if (!buf)
		return NULL;

	memset(buf, 0xff, size / 8);

	unsigned trailing_bits = size % 8;
	if (trailing_bits)
		buf[size / 8] = (1 << trailing_bits) - 1;

	return buf;
}

void *buf_set_buf(const void *_src, unsigned src_start,
	void *_dst, unsigned dst_start, unsigned len)
{
	const uint8_t *src = _src;
	uint8_t *dst = _dst;
	unsigned i, sb, db, sq, dq, lb, lq;

	sb = src_start / 8;
	db = dst_start / 8;
	sq = src_start % 8;
	dq = dst_start % 8;
	lb = len / 8;
	lq = len % 8;

	src += sb;
	dst += db;

	/* check if both buffers are on byte boundary and
	 * len is a multiple of 8bit so we can simple copy
	 * the buffer */
	if ((sq == 0) && (dq == 0) &&  (lq == 0)) {
		for (i = 0; i < lb; i++)
			*dst++ = *src++;
		return _dst;
	}

	/* fallback to slow bit copy */
	for (i = 0; i < len; i++) {
		if (((*src >> (sq&7)) & 1) == 1)
			*dst |= 1 << (dq&7);
		else
			*dst &= ~(1 << (dq&7));
		if (sq++ == 7) {
			sq = 0;
			src++;
		}
		if (dq++ == 7) {
			dq = 0;
			dst++;
		}
	}

	return _dst;
}


/*
 * macro is used to print the svf hex buffer at desired debug level
 * DEBUG, INFO, ERROR, USER
 */
#define SVF_BUF_LOG(_lvl, _buf, _nbits, _desc)							\
	svf_hexbuf_print(_lvl,  __FILE__, __LINE__, __func__, _buf, _nbits, _desc)

static void svf_hexbuf_print(int dbg_lvl, const char *file, unsigned line,
							 const char *function, const uint8_t *buf,
							 int bit_len, const char *desc)
{
	int i, j;
	int byte_len = (bit_len +7) / 8;
	printf("%s: \n", desc);
	for (i = byte_len; i--; i > 0) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

static int svf_realloc_buffers(size_t len)
{
	void *ptr;

	LOG_DEBUG("svf_realloc_buffers(%d)\n", len);

	ptr = realloc(svf_tdi_buffer, len);
	if (!ptr)
		return ERROR_FAIL;
	svf_tdi_buffer = ptr;

	ptr = realloc(svf_tdo_buffer, len);
	if (!ptr)
		return ERROR_FAIL;
	svf_tdo_buffer = ptr;

	ptr = realloc(svf_mask_buffer, len);
	if (!ptr)
		return ERROR_FAIL;
	svf_mask_buffer = ptr;

	svf_buffer_size = len;

	return ERROR_OK;
}

static void svf_free_xxd_para(struct svf_xxr_para *para)
{
	if (NULL != para) {
		if (para->tdi != NULL) {
			free(para->tdi);
			para->tdi = NULL;
		}
		if (para->tdo != NULL) {
			free(para->tdo);
			para->tdo = NULL;
		}
		if (para->mask != NULL) {
			free(para->mask);
			para->mask = NULL;
		}
		if (para->smask != NULL) {
			free(para->smask);
			para->smask = NULL;
		}
	}
}

static int svf_getline(char **lineptr, size_t *n, FILE *stream)
{
#define MIN_CHUNK 16	/* Buffer is increased by this size each time as required */
	size_t i = 0;

	if (*lineptr == NULL) {
		*n = MIN_CHUNK;
		*lineptr = malloc(*n);
		if (!*lineptr)
			return -1;
	}

	(*lineptr)[0] = fgetc(stream);
	while ((*lineptr)[i] != '\n') {
		(*lineptr)[++i] = fgetc(stream);
		if (feof(stream)) {
			(*lineptr)[0] = 0;
			return -1;
		}
		if ((i + 2) > *n) {
			*n += MIN_CHUNK;
			*lineptr = realloc(*lineptr, *n);
		}
	}

	(*lineptr)[++i] = 0;

	return sizeof(*lineptr);
}

#define SVFP_CMD_INC_CNT 1024
static int svf_read_command_from_file(FILE *fd)
{
	unsigned char ch;
	int i = 0;
	size_t cmd_pos = 0;
	int cmd_ok = 0, slash = 0;

	if (svf_getline(&svf_read_line, &svf_read_line_size, svf_fd) <= 0)
		return ERROR_FAIL;
	svf_line_number++;
	ch = svf_read_line[0];
	while (!cmd_ok && (ch != 0)) {
		switch (ch) {
			case '!':
				slash = 0;
				if (svf_getline(&svf_read_line, &svf_read_line_size, svf_fd) <= 0)
					return ERROR_FAIL;
				svf_line_number++;
				i = -1;
				break;
			case '/':
				if (++slash == 2) {
					slash = 0;
					if (svf_getline(&svf_read_line, &svf_read_line_size,
						svf_fd) <= 0)
						return ERROR_FAIL;
					svf_line_number++;
					i = -1;
				}
				break;
			case ';':
				slash = 0;
				cmd_ok = 1;
				break;
			case '\n':
				svf_line_number++;
				if (svf_getline(&svf_read_line, &svf_read_line_size, svf_fd) <= 0)
					return ERROR_FAIL;
				i = -1;
				/* fallthrough */
			case '\r':
				slash = 0;
				/* Don't save '\r' and '\n' if no data is parsed */
				if (!cmd_pos)
					break;
				/* fallthrough */
			default:
				/* The parsing code currently expects a space
				 * before parentheses -- "TDI (123)".  Also a
				 * space afterwards -- "TDI (123) TDO(456)".
				 * But such spaces are optional... instead of
				 * parser updates, cope with that by adding the
				 * spaces as needed.
				 *
				 * Ensure there are 3 bytes available, for:
				 *  - current character
				 *  - added space.
				 *  - terminating NUL ('\0')
				 */
				if (cmd_pos + 3 > svf_command_buffer_size) {
					svf_command_buffer = realloc(svf_command_buffer, cmd_pos + 3);
					svf_command_buffer_size = cmd_pos + 3;
					if (svf_command_buffer == NULL) {
						LOG_ERROR("not enough memory");
						return ERROR_FAIL;
					}
				}

				/* insert a space before '(' */
				if ('(' == ch)
					svf_command_buffer[cmd_pos++] = ' ';

				svf_command_buffer[cmd_pos++] = (char)toupper(ch);

				/* insert a space after ')' */
				if (')' == ch)
					svf_command_buffer[cmd_pos++] = ' ';
				break;
		}
		ch = svf_read_line[++i];
	}

	if (cmd_ok) {
		svf_command_buffer[cmd_pos] = '\0';
		return ERROR_OK;
	} else
		return ERROR_FAIL;
}

static int svf_parse_cmd_string(char *str, int len, char **argus, int *num_of_argu)
{
	int pos = 0, num = 0, space_found = 1, in_bracket = 0;

	while (pos < len) {
		switch (str[pos]) {
			case '!':
			case '/':
				LOG_ERROR("fail to parse svf command");
				return ERROR_FAIL;
			case '(':
				in_bracket = 1;
				goto parse_char;
			case ')':
				in_bracket = 0;
				goto parse_char;
			default:
parse_char:
				if (!in_bracket && isspace((int) str[pos])) {
					space_found = 1;
					str[pos] = '\0';
				} else if (space_found) {
					argus[num++] = &str[pos];
					space_found = 0;
				}
				break;
		}
		pos++;
	}

	if (num == 0)
		return ERROR_FAIL;

	*num_of_argu = num;

	return ERROR_OK;
}

bool svf_tap_state_is_stable(tap_state_t state)
{
	return (TAP_RESET == state) || (TAP_IDLE == state)
			|| (TAP_DRPAUSE == state) || (TAP_IRPAUSE == state);
}

static int svf_find_string_in_array(char *str, char **strs, int num_of_element)
{
	int i;

	for (i = 0; i < num_of_element; i++) {
		if (!strcmp(str, strs[i]))
			return i;
	}
	return 0xFF;
}

static int svf_adjust_array_length(uint8_t **arr, int orig_bit_len, int new_bit_len)
{
	int new_byte_len = (new_bit_len + 7) >> 3;

	if ((NULL == *arr) || (((orig_bit_len + 7) >> 3) < ((new_bit_len + 7) >> 3))) {
		if (*arr != NULL) {
			free(*arr);
			*arr = NULL;
		}
		*arr = malloc(new_byte_len);
		if (NULL == *arr) {
			LOG_ERROR("not enough memory");
			return ERROR_FAIL;
		}
		memset(*arr, 0, new_byte_len);
	}
	return ERROR_OK;
}

static int svf_set_padding(struct svf_xxr_para *para, int len, unsigned char tdi)
{
	int error = ERROR_OK;
	error |= svf_adjust_array_length(&para->tdi, para->len, len);
	memset(para->tdi, tdi, (len + 7) >> 3);
	error |= svf_adjust_array_length(&para->tdo, para->len, len);
	error |= svf_adjust_array_length(&para->mask, para->len, len);
	para->len = len;
	para->data_mask = XXR_TDI;

	return error;
}

static int svf_copy_hexstring_to_binary(char *str, uint8_t **bin, int orig_bit_len, int bit_len)
{
	int i, str_len = strlen(str), str_hbyte_len = (bit_len + 3) >> 2;
	uint8_t ch = 0;

	if (ERROR_OK != svf_adjust_array_length(bin, orig_bit_len, bit_len)) {
		LOG_ERROR("fail to adjust length of array");
		return ERROR_FAIL;
	}

	/* fill from LSB (end of str) to MSB (beginning of str) */
	for (i = 0; i < str_hbyte_len; i++) {
		ch = 0;
		while (str_len > 0) {
			ch = str[--str_len];

			/* Skip whitespace.  The SVF specification (rev E) is
			 * deficient in terms of basic lexical issues like
			 * where whitespace is allowed.  Long bitstrings may
			 * require line ends for correctness, since there is
			 * a hard limit on line length.
			 */
			if (!isspace(ch)) {
				if ((ch >= '0') && (ch <= '9')) {
					ch = ch - '0';
					break;
				} else if ((ch >= 'A') && (ch <= 'F')) {
					ch = ch - 'A' + 10;
					break;
				} else {
					LOG_ERROR("invalid hex string");
					return ERROR_FAIL;
				}
			}

			ch = 0;
		}

		/* write bin */
		if (i % 2) {
			/* MSB */
			(*bin)[i / 2] |= ch << 4;
		} else {
			/* LSB */
			(*bin)[i / 2] = 0;
			(*bin)[i / 2] |= ch;
		}
	}

	/* consume optional leading '0' MSBs or whitespace */
	while (str_len > 0 && ((str[str_len - 1] == '0')
			|| isspace((int) str[str_len - 1])))
		str_len--;

	/* check validity: we must have consumed everything */
	if (str_len > 0 || (ch & ~((2 << ((bit_len - 1) % 4)) - 1)) != 0) {
		LOG_ERROR("value execeeds length");
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int svf_check_tdo(void)
{
	int i, len, index_var;

	for (i = 0; i < svf_check_tdo_para_index; i++) {
		index_var = svf_check_tdo_para[i].buffer_offset;
		len = svf_check_tdo_para[i].bit_len;
		if ((svf_check_tdo_para[i].enabled)
				&& buf_cmp_mask(&svf_tdi_buffer[index_var], &svf_tdo_buffer[index_var],
				&svf_mask_buffer[index_var], len)) {
			LOG_ERROR("tdo check error at line %d",
					  svf_check_tdo_para[i].line_num);
			SVF_BUF_LOG(LOG_ERROR, &svf_tdi_buffer[index_var], len, "READ");
			SVF_BUF_LOG(LOG_ERROR, &svf_tdo_buffer[index_var], len, "WANT");
			SVF_BUF_LOG(LOG_ERROR, &svf_mask_buffer[index_var], len, "MASK");

			if (svf_ignore_error == 0)
				return ERROR_FAIL;
			else
				svf_ignore_error++;
		}
	}
	svf_check_tdo_para_index = 0;

	return ERROR_OK;
}

static int svf_add_check_para(uint8_t enabled, int buffer_offset, int bit_len)
{
	if (svf_check_tdo_para_index >= SVF_CHECK_TDO_PARA_SIZE) {
		LOG_ERROR("toooooo many operation undone");
		return ERROR_FAIL;
	}

	svf_check_tdo_para[svf_check_tdo_para_index].line_num = svf_line_number;
	svf_check_tdo_para[svf_check_tdo_para_index].bit_len = bit_len;
	svf_check_tdo_para[svf_check_tdo_para_index].enabled = enabled;
	svf_check_tdo_para[svf_check_tdo_para_index].buffer_offset = buffer_offset;
	svf_check_tdo_para_index++;

	return ERROR_OK;
}

static int svf_run_command(char *cmd_str)
{
	char *argus[256], command;
	int num_of_argu = 0, i;

	/* tmp variable */
	int i_tmp;

	/* for RUNTEST */
	int run_count;
	float min_time;
	/* for XXR */
	struct svf_xxr_para *xxr_para_tmp;
	uint8_t **pbuffer_tmp;
	struct scan_field field;
	/* for STATE */
	tap_state_t *path = NULL, state;
	/* flag padding commands skipped due to -tap command */
	int padding_command_skipped = 0;

	LOG_INFO("%s", cmd_str);
	if (ERROR_OK != svf_parse_cmd_string(cmd_str, strlen(cmd_str), argus, &num_of_argu))
		return ERROR_FAIL;

	/* NOTE: we're a bit loose here, because we ignore case in
	 * TAP state names (instead of insisting on uppercase).
	 */

	command = svf_find_string_in_array(argus[0],
			(char **)svf_command_name, ARRAY_SIZE(svf_command_name));
	switch (command) {
		case LOOP:
			if (ERROR_OK != svf_check_tdo())
				return ERROR_FAIL;
			if (num_of_argu != 2) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}

			loop = atoi(argus[1]);
			file_offset = ftell(svf_fd);
			loop--;
			break;
		case ENDLOOP:
			if (loop > 0) {
				if (ERROR_OK == svf_check_tdo()) {
					loop = 0;
					break;
				} else {
					fseek(svf_fd, file_offset, SEEK_SET);
					loop--;
				}
			}
			break;
		case ENDDR:
		case ENDIR:
			if (num_of_argu != 2) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}

			i_tmp = tap_state_by_name(argus[1]);

			if (svf_tap_state_is_stable(i_tmp)) {
				if (command == ENDIR) {
					svf_para.ir_end_state = i_tmp;
					LOG_DEBUG("\tIR end_state = %s",
							tap_state_name(i_tmp));
				} else {
					svf_para.dr_end_state = i_tmp;
					LOG_DEBUG("\tDR end_state = %s",
							tap_state_name(i_tmp));
				}
			} else {
				LOG_ERROR("%s: %s is not a stable state",
						argus[0], argus[1]);
				return ERROR_FAIL;
			}
			break;
		case FREQUENCY:
			if ((num_of_argu != 1) && (num_of_argu != 3)) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}
			if (1 == num_of_argu) {
				/* TODO: set jtag speed to full speed */
				svf_para.frequency = 0;
			} else {
				if (strcmp(argus[2], "HZ")) {
					LOG_ERROR("HZ not found in FREQUENCY command");
					return ERROR_FAIL;
				}
				//if (ERROR_OK != svf_execute_tap())
				//	return ERROR_FAIL;
				svf_para.frequency = atof(argus[1]);
				/* TODO: set jtag speed to */
				if (svf_para.frequency > 0 && !frequency) {
					LOG_DEBUG("\tfrequency = %f", svf_para.frequency);
					ast_set_jtag_freq((unsigned int)svf_para.frequency);
				}
			}
			break;
		case HDR:
			if (svf_tap_is_specified) {
				padding_command_skipped = 1;
				break;
			}
			xxr_para_tmp = &svf_para.hdr_para;
			goto XXR_common;
		case HIR:
			if (svf_tap_is_specified) {
				padding_command_skipped = 1;
				break;
			}
			xxr_para_tmp = &svf_para.hir_para;
			goto XXR_common;
		case TDR:
			if (svf_tap_is_specified) {
				padding_command_skipped = 1;
				break;
			}
			xxr_para_tmp = &svf_para.tdr_para;
			goto XXR_common;
		case TIR:
			if (svf_tap_is_specified) {
				padding_command_skipped = 1;
				break;
			}
			xxr_para_tmp = &svf_para.tir_para;
			goto XXR_common;
		case SDR:
			xxr_para_tmp = &svf_para.sdr_para;
			goto XXR_common;
		case SIR:
			xxr_para_tmp = &svf_para.sir_para;
			goto XXR_common;
XXR_common:
			/* XXR length [TDI (tdi)] [TDO (tdo)][MASK (mask)] [SMASK (smask)] */
			if ((num_of_argu > 10) || (num_of_argu % 2)) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}
			i_tmp = xxr_para_tmp->len;
			xxr_para_tmp->len = atoi(argus[1]);
			/* If we are to enlarge the buffers, all parts of xxr_para_tmp
			 * need to be freed */
			if (i_tmp < xxr_para_tmp->len) {
				free(xxr_para_tmp->tdi);
				xxr_para_tmp->tdi = NULL;
				free(xxr_para_tmp->tdo);
				xxr_para_tmp->tdo = NULL;
				free(xxr_para_tmp->mask);
				xxr_para_tmp->mask = NULL;
				free(xxr_para_tmp->smask);
				xxr_para_tmp->smask = NULL;
			}
			xxr_para_tmp->data_mask = 0;
			for (i = 2; i < num_of_argu; i += 2) {
				if ((strlen(argus[i + 1]) < 3) || (argus[i + 1][0] != '(') ||
				(argus[i + 1][strlen(argus[i + 1]) - 1] != ')')) {
					LOG_ERROR("data section error");
					return ERROR_FAIL;
				}
				argus[i + 1][strlen(argus[i + 1]) - 1] = '\0';
				/* TDI, TDO, MASK, SMASK */
				if (!strcmp(argus[i], "TDI")) {
					/* TDI */
					pbuffer_tmp = &xxr_para_tmp->tdi;
					xxr_para_tmp->data_mask |= XXR_TDI;
				} else if (!strcmp(argus[i], "TDO")) {
					/* TDO */
					pbuffer_tmp = &xxr_para_tmp->tdo;
					xxr_para_tmp->data_mask |= XXR_TDO;
				} else if (!strcmp(argus[i], "MASK") || !strcmp(argus[i], "CMASK")) {
					/* MASK */
					pbuffer_tmp = &xxr_para_tmp->mask;
					xxr_para_tmp->data_mask |= XXR_MASK;
				} else if (!strcmp(argus[i], "SMASK")) {
					/* SMASK */
					pbuffer_tmp = &xxr_para_tmp->smask;
					xxr_para_tmp->data_mask |= XXR_SMASK;
				} else {
					LOG_ERROR("unknow parameter: %s", argus[i]);
					return ERROR_FAIL;
				}
				if (ERROR_OK !=
				svf_copy_hexstring_to_binary(&argus[i + 1][1], pbuffer_tmp, i_tmp,
					xxr_para_tmp->len)) {
					LOG_ERROR("fail to parse hex value");
					return ERROR_FAIL;
				}
				//SVF_BUF_LOG(DEBUG, *pbuffer_tmp, xxr_para_tmp->len, argus[i]);
			}
			/* If a command changes the length of the last scan of the same type and the
			 * MASK parameter is absent, */
			/* the mask pattern used is all cares */
			if (!(xxr_para_tmp->data_mask & XXR_MASK) && (i_tmp != xxr_para_tmp->len)) {
				/* MASK not defined and length changed */
				if (ERROR_OK !=
				svf_adjust_array_length(&xxr_para_tmp->mask, i_tmp,
					xxr_para_tmp->len)) {
					LOG_ERROR("fail to adjust length of array");
					return ERROR_FAIL;
				}
				buf_set_ones(xxr_para_tmp->mask, xxr_para_tmp->len);
			}
			/* If TDO is absent, no comparison is needed, set the mask to 0 */
			if (!(xxr_para_tmp->data_mask & XXR_TDO)) {
				if (NULL == xxr_para_tmp->tdo) {
					if (ERROR_OK !=
					svf_adjust_array_length(&xxr_para_tmp->tdo, i_tmp,
						xxr_para_tmp->len)) {
						LOG_ERROR("fail to adjust length of array");
						return ERROR_FAIL;
					}
				}
				if (NULL == xxr_para_tmp->mask) {
					if (ERROR_OK !=
					svf_adjust_array_length(&xxr_para_tmp->mask, i_tmp,
						xxr_para_tmp->len)) {
						LOG_ERROR("fail to adjust length of array");
						return ERROR_FAIL;
					}
				}
				memset(xxr_para_tmp->mask, 0, (xxr_para_tmp->len + 7) >> 3);
			}
			/* do scan if necessary */
			if (SDR == command) {
				/* check buffer size first, reallocate if necessary */
				i = svf_para.hdr_para.len + svf_para.sdr_para.len +
						svf_para.tdr_para.len;
				if ((svf_buffer_size - svf_buffer_index) < ((i + 7) >> 3)) {
					/* reallocate buffer */
					if (svf_realloc_buffers(svf_buffer_index + ((i + 7) >> 3)) != ERROR_OK) {
						LOG_ERROR("not enough memory");
						return ERROR_FAIL;
					}
				}

				/* assemble dr data */
				i = 0;
				buf_set_buf(svf_para.hdr_para.tdi,
						0,
						&svf_tdi_buffer[svf_buffer_index],
						i,
						svf_para.hdr_para.len);
				i += svf_para.hdr_para.len;
				buf_set_buf(svf_para.sdr_para.tdi,
						0,
						&svf_tdi_buffer[svf_buffer_index],
						i,
						svf_para.sdr_para.len);
				i += svf_para.sdr_para.len;
				buf_set_buf(svf_para.tdr_para.tdi,
						0,
						&svf_tdi_buffer[svf_buffer_index],
						i,
						svf_para.tdr_para.len);
				i += svf_para.tdr_para.len;

				/* add check data */
				if (svf_para.sdr_para.data_mask & XXR_TDO) {
					/* assemble dr mask data */
					i = 0;
					buf_set_buf(svf_para.hdr_para.mask,
							0,
							&svf_mask_buffer[svf_buffer_index],
							i,
							svf_para.hdr_para.len);
					i += svf_para.hdr_para.len;
					buf_set_buf(svf_para.sdr_para.mask,
							0,
							&svf_mask_buffer[svf_buffer_index],
							i,
							svf_para.sdr_para.len);
					i += svf_para.sdr_para.len;
					buf_set_buf(svf_para.tdr_para.mask,
							0,
							&svf_mask_buffer[svf_buffer_index],
							i,
							svf_para.tdr_para.len);

					/* assemble dr check data */
					i = 0;
					buf_set_buf(svf_para.hdr_para.tdo,
							0,
							&svf_tdo_buffer[svf_buffer_index],
							i,
							svf_para.hdr_para.len);
					i += svf_para.hdr_para.len;
					buf_set_buf(svf_para.sdr_para.tdo,
							0,
							&svf_tdo_buffer[svf_buffer_index],
							i,
							svf_para.sdr_para.len);
					i += svf_para.sdr_para.len;
					buf_set_buf(svf_para.tdr_para.tdo,
							0,
							&svf_tdo_buffer[svf_buffer_index],
							i,
							svf_para.tdr_para.len);
					i += svf_para.tdr_para.len;

					svf_add_check_para(1, svf_buffer_index, i);
				} else
					svf_add_check_para(0, svf_buffer_index, i);
				field.num_bits = i;
				field.out_value = &svf_tdi_buffer[svf_buffer_index];
				/* TODO: If without TDO no need to sned data back*/
				field.in_value = &svf_tdi_buffer[svf_buffer_index];
				if (!svf_nil) {
					/* NOTE:  doesn't use SVF-specified state paths */
					LOG_DEBUG("dr_scan: num_bits %d end_state %s\n",
						field.num_bits, tap_state_name(svf_para.dr_end_state));
					ast_jtag_xfer(tap_mapping[svf_para.dr_end_state], field.num_bits,
						field.out_value,
						field.in_value, JTAG_SDR_XFER);
				}

				svf_buffer_index += (i + 7) >> 3;
			} else if (SIR == command) {
				/* check buffer size first, reallocate if necessary */
				i = svf_para.hir_para.len + svf_para.sir_para.len +
						svf_para.tir_para.len;
				if ((svf_buffer_size - svf_buffer_index) < ((i + 7) >> 3)) {
					if (svf_realloc_buffers(svf_buffer_index + ((i + 7) >> 3)) != ERROR_OK) {
						LOG_ERROR("not enough memory");
						return ERROR_FAIL;
					}
				}

				/* assemble ir data */
				i = 0;
				buf_set_buf(svf_para.hir_para.tdi,
						0,
						&svf_tdi_buffer[svf_buffer_index],
						i,
						svf_para.hir_para.len);
				i += svf_para.hir_para.len;
				buf_set_buf(svf_para.sir_para.tdi,
						0,
						&svf_tdi_buffer[svf_buffer_index],
						i,
						svf_para.sir_para.len);
				i += svf_para.sir_para.len;
				buf_set_buf(svf_para.tir_para.tdi,
						0,
						&svf_tdi_buffer[svf_buffer_index],
						i,
						svf_para.tir_para.len);
				i += svf_para.tir_para.len;

				/* add check data */
				if (svf_para.sir_para.data_mask & XXR_TDO) {
					/* assemble dr mask data */
					i = 0;
					buf_set_buf(svf_para.hir_para.mask,
							0,
							&svf_mask_buffer[svf_buffer_index],
							i,
							svf_para.hir_para.len);
					i += svf_para.hir_para.len;
					buf_set_buf(svf_para.sir_para.mask,
							0,
							&svf_mask_buffer[svf_buffer_index],
							i,
							svf_para.sir_para.len);
					i += svf_para.sir_para.len;
					buf_set_buf(svf_para.tir_para.mask,
							0,
							&svf_mask_buffer[svf_buffer_index],
							i,
							svf_para.tir_para.len);

					/* assemble dr check data */
					i = 0;
					buf_set_buf(svf_para.hir_para.tdo,
							0,
							&svf_tdo_buffer[svf_buffer_index],
							i,
							svf_para.hir_para.len);
					i += svf_para.hir_para.len;
					buf_set_buf(svf_para.sir_para.tdo,
							0,
							&svf_tdo_buffer[svf_buffer_index],
							i,
							svf_para.sir_para.len);
					i += svf_para.sir_para.len;
					buf_set_buf(svf_para.tir_para.tdo,
							0,
							&svf_tdo_buffer[svf_buffer_index],
							i,
							svf_para.tir_para.len);
					i += svf_para.tir_para.len;

					svf_add_check_para(1, svf_buffer_index, i);
				} else
					svf_add_check_para(0, svf_buffer_index, i);
				field.num_bits = i;
				field.out_value = &svf_tdi_buffer[svf_buffer_index];
				field.in_value =  &svf_tdi_buffer[svf_buffer_index];
				if (!svf_nil) {
					/* NOTE:  doesn't use SVF-specified state paths */
					LOG_DEBUG("ir_scan: num_bits %d end_state %s\n",
						field.num_bits, tap_state_name(svf_para.ir_end_state));
					ast_jtag_xfer(tap_mapping[svf_para.ir_end_state], field.num_bits,
						field.out_value,
						field.in_value, JTAG_SIR_XFER);
				}

				svf_buffer_index += (i + 7) >> 3;
			}
			break;
		case PIO:
		case PIOMAP:
			LOG_ERROR("PIO and PIOMAP are not supported");
			return ERROR_FAIL;
			break;
		case RUNTEST:
			/* RUNTEST [run_state] run_count run_clk [min_time SEC [MAXIMUM max_time
			 * SEC]] [ENDSTATE end_state] */
			/* RUNTEST [run_state] min_time SEC [MAXIMUM max_time SEC] [ENDSTATE
			 * end_state] */
			if ((num_of_argu < 3) || (num_of_argu > 11)) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}
			/* init */
			run_count = 0;
			min_time = 0;
			i = 1;

			/* run_state */
			i_tmp = tap_state_by_name(argus[i]);
			if (i_tmp != TAP_INVALID) {
				if (svf_tap_state_is_stable(i_tmp)) {
					svf_para.runtest_run_state = i_tmp;

					/* When a run_state is specified, the new
					 * run_state becomes the default end_state.
					 */
					svf_para.runtest_end_state = i_tmp;
					LOG_DEBUG("\trun_state = %s", tap_state_name(i_tmp));
					i++;
				} else {
					LOG_ERROR("%s: %s is not a stable state", argus[0], tap_state_name(i_tmp));
					return ERROR_FAIL;
				}
			}

			/* run_count run_clk */
			if (((i + 2) <= num_of_argu) && strcmp(argus[i + 1], "SEC")) {
				if (!strcmp(argus[i + 1], "TCK")) {
					/* clock source is TCK */
					run_count = atoi(argus[i]);
					LOG_DEBUG("\trun_count@TCK = %d", run_count);
				} else {
					LOG_ERROR("%s not supported for clock", argus[i + 1]);
					return ERROR_FAIL;
				}
				i += 2;
			}
			/* min_time SEC */
			if (((i + 2) <= num_of_argu) && !strcmp(argus[i + 1], "SEC")) {
				min_time = atof(argus[i]);
				LOG_DEBUG("\tmin_time = %fs", min_time);
				i += 2;
			}
			/* MAXIMUM max_time SEC */
			if (((i + 3) <= num_of_argu) &&
			!strcmp(argus[i], "MAXIMUM") && !strcmp(argus[i + 2], "SEC")) {
				float max_time = 0;
				max_time = atof(argus[i + 1]);
				LOG_DEBUG("\tmax_time = %fs", max_time);
				i += 3;
			}
			/* ENDSTATE end_state */
			if (((i + 2) <= num_of_argu) && !strcmp(argus[i], "ENDSTATE")) {
				i_tmp = tap_state_by_name(argus[i + 1]);

				if (svf_tap_state_is_stable(i_tmp)) {
					svf_para.runtest_end_state = i_tmp;
					LOG_DEBUG("\tend_state = %s", tap_state_name(i_tmp));
				} else {
					LOG_ERROR("%s: %s is not a stable state", argus[0], tap_state_name(i_tmp));
					return ERROR_FAIL;
				}
				i += 2;
			}

			/* all parameter should be parsed */
			if (i == num_of_argu) {
				/* FIXME handle statemove failures */
				uint32_t min_usec = 1000000 * min_time;

				/* enter into run_state if necessary */
				if (svf_tap_state_is_stable(svf_para.runtest_run_state))
					ast_jtag_run_test_idle(tap_mapping[svf_para.runtest_run_state], run_count);
				else {
						LOG_ERROR("Aspeed software can't support runtest to %s:%d yet",
								tap_state_name(svf_para.runtest_run_state),
								svf_para.runtest_run_state);
						return ERROR_FAIL;
					}
				if (min_usec > 0)
				{
					LOG_DEBUG("sleep %lu usec\n", min_usec);
					usleep(min_usec);
				}

				/* move to end_state if necessary */
				if (svf_para.runtest_end_state != svf_para.runtest_run_state) {
					if (svf_tap_state_is_stable(svf_para.runtest_end_state))
						ast_jtag_run_test_idle(tap_mapping[svf_para.runtest_end_state], run_count);
					else
					{
						LOG_ERROR("Aspeed software can't support runtest to %s:%d yet",
								tap_state_name(svf_para.runtest_end_state),
								svf_para.runtest_end_state);
						return ERROR_FAIL;
					}
				}
			} else {
				LOG_ERROR("fail to parse parameter of RUNTEST, %d out of %d is parsed",
						i,
						num_of_argu);
				return ERROR_FAIL;
			}
			break;
		case STATE:
			/* STATE [pathstate1 [pathstate2 ...[pathstaten]]] stable_state */
			if (num_of_argu < 2) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}
			if (num_of_argu > 2) {
				/* STATE pathstate1 ... stable_state */
				path = malloc((num_of_argu - 1) * sizeof(tap_state_t));
				if (NULL == path) {
					LOG_ERROR("not enough memory");
					return ERROR_FAIL;
				}
				num_of_argu--;	/* num of path */
				i_tmp = 1;		/* path is from parameter 1 */
				for (i = 0; i < num_of_argu; i++, i_tmp++) {
					path[i] = tap_state_by_name(argus[i_tmp]);
					if (path[i] == TAP_INVALID) {
						LOG_ERROR("%s: %s is not a valid state", argus[0], argus[i_tmp]);
						free(path);
						return ERROR_FAIL;
					}
				}
				if (num_of_argu > 0) {
					/* execute last path if necessary */
					if (svf_tap_state_is_stable(path[num_of_argu - 1])) {
						/* last state MUST be stable state */
						ast_jtag_run_test_idle(tap_mapping[path[num_of_argu - 1]], 0);
						LOG_DEBUG("\tmove to %s by path_move",
								tap_state_name(path[num_of_argu - 1]));
					} else {
						LOG_ERROR("%s: %s is not a stable state",
								argus[0],
								tap_state_name(path[num_of_argu - 1]));
						free(path);
						return ERROR_FAIL;
					}
				}

				free(path);
				path = NULL;
			} else {
				/* STATE stable_state */
				state = tap_state_by_name(argus[1]);
				if (svf_tap_state_is_stable(state)) {
					LOG_DEBUG("\tmove to %s",
							tap_state_name(state));
					/* FIXME handle statemove failures */
					ast_jtag_run_test_idle(tap_mapping[state], 0);
				} else {
					LOG_ERROR("%s: %s is not a stable state",
							argus[0], tap_state_name(state));
					return ERROR_FAIL;
				}
			}
			break;
		case TRST:
			/* TRST trst_mode */
			if (num_of_argu != 2) {
				LOG_ERROR("invalid parameter of %s", argus[0]);
				return ERROR_FAIL;
			}
			if (svf_para.trst_mode != TRST_ABSENT) {
				//if (ERROR_OK != svf_execute_tap())
				//	return ERROR_FAIL;
				i_tmp = svf_find_string_in_array(argus[1],
						(char **)svf_trst_mode_name,
						ARRAY_SIZE(svf_trst_mode_name));
				switch (i_tmp) {
				case TRST_ON:
					//if (!svf_nil)
					//	jtag_add_reset(1, 0);
					break;
				case TRST_Z:
				case TRST_OFF:
					//if (!svf_nil)
					//	jtag_add_reset(0, 0);
					break;
				case TRST_ABSENT:
					break;
				default:
					LOG_ERROR("unknown TRST mode: %s", argus[1]);
					return ERROR_FAIL;
				}
				svf_para.trst_mode = i_tmp;
				LOG_DEBUG("\ttrst_mode = %s", svf_trst_mode_name[svf_para.trst_mode]);
			} else {
				LOG_ERROR("can not accpet TRST command if trst_mode is ABSENT");
				return ERROR_FAIL;
			}
			break;
		default:
			LOG_ERROR("invalid svf command: %s", argus[0]);
			return ERROR_FAIL;
			break;
	}
	if (ERROR_OK != svf_check_tdo())
		return ERROR_FAIL;
	return ERROR_OK;
}


int handle_svf_command(char *filename)
{
	int command_num = 0;
	int ret = ERROR_OK;

	/* parse command line */
	svf_quiet = 0;
	svf_nil = 0;
	svf_ignore_error = 0;

	svf_fd = fopen(filename, "r");
	if (svf_fd == NULL) {
		LOG_ERROR("failed to open %s\n", filename);
		return -1;
	} else
		LOG_DEBUG("svf processing file: \"%s\"", filename);

	/* init */
	svf_line_number = 0;
	svf_command_buffer_size = 0;

	svf_check_tdo_para_index = 0;
	svf_check_tdo_para = malloc(sizeof(struct svf_check_tdo_para) * SVF_CHECK_TDO_PARA_SIZE);
	if (NULL == svf_check_tdo_para)
	{
		LOG_ERROR("not enough memory");
		ret = ERROR_FAIL;
		goto free_all;
	}

	svf_buffer_index = 0;
	/* double the buffer size */
	/* in case current command cannot be committed, and next command is a bit scan command */
	/* here is 32K bits for this big scan command, it should be enough */
	/* buffer will be reallocated if buffer size is not enough */
	if (svf_realloc_buffers(2 * SVF_MAX_BUFFER_SIZE_TO_COMMIT) != ERROR_OK) {
		ret = ERROR_FAIL;
		goto free_all;
	}

	memcpy(&svf_para, &svf_para_init, sizeof(svf_para));

	while (ERROR_OK == svf_read_command_from_file(svf_fd)) {
		int c;
		/* Run Command */
		if (ERROR_OK != svf_run_command(svf_command_buffer)) {
			LOG_ERROR("fail to run command at line %d", svf_line_number);
			ret = ERROR_FAIL;
			break;
		}
		command_num++;
	}

	svf_check_tdo();
free_all:

	fclose(svf_fd);
	svf_fd = 0;

	/* free buffers */
	if (svf_command_buffer) {
		free(svf_command_buffer);
		svf_command_buffer = NULL;
		svf_command_buffer_size = 0;
	}
	if (svf_check_tdo_para) {
		free(svf_check_tdo_para);
		svf_check_tdo_para = NULL;
		svf_check_tdo_para_index = 0;
	}
	if (svf_tdi_buffer) {
		free(svf_tdi_buffer);
		svf_tdi_buffer = NULL;
	}
	if (svf_tdo_buffer) {
		free(svf_tdo_buffer);
		svf_tdo_buffer = NULL;
	}
	if (svf_mask_buffer) {
		free(svf_mask_buffer);
		svf_mask_buffer = NULL;
	}
	svf_buffer_index = 0;
	svf_buffer_size = 0;

	svf_free_xxd_para(&svf_para.hdr_para);
	svf_free_xxd_para(&svf_para.hir_para);
	svf_free_xxd_para(&svf_para.tdr_para);
	svf_free_xxd_para(&svf_para.tir_para);
	svf_free_xxd_para(&svf_para.sdr_para);
	svf_free_xxd_para(&svf_para.sir_para);

	svf_ignore_error = 0;
	return ret;
}