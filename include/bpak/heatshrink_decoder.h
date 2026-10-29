/*
 * Copyright (c) 2013-2015, Scott Vokes <vokes.s@gmail.com>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HEATSHRINK_DECODER_H
#define HEATSHRINK_DECODER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version 0.4.1 */
#define HEATSHRINK_VERSION_MAJOR 0
#define HEATSHRINK_VERSION_MINOR 4
#define HEATSHRINK_VERSION_PATCH 1

#define HEATSHRINK_MIN_WINDOW_BITS 4
#define HEATSHRINK_MAX_WINDOW_BITS 15

#define HEATSHRINK_MIN_LOOKAHEAD_BITS 3

#define HEATSHRINK_LITERAL_MARKER 0x01
#define HEATSHRINK_BACKREF_MARKER 0x00

/* Required parameters for static configuration */
#define HEATSHRINK_STATIC_INPUT_BUFFER_SIZE 256
#define HEATSHRINK_STATIC_WINDOW_BITS       8
#define HEATSHRINK_STATIC_LOOKAHEAD_BITS    7

typedef enum {
    HSDR_SINK_OK,              /* data sunk, ready to poll */
    HSDR_SINK_FULL,            /* out of space in internal buffer */
    HSDR_SINK_ERROR_NULL = -1, /* NULL argument */
} HSD_sink_res;

typedef enum {
    HSDR_POLL_EMPTY, /* input exhausted */
    HSDR_POLL_MORE, /* more data remaining, call again w/ fresh output buffer */
    HSDR_POLL_ERROR_NULL = -1, /* NULL arguments */
    HSDR_POLL_ERROR_UNKNOWN = -2,
} HSD_poll_res;

typedef enum {
    HSDR_FINISH_DONE,            /* output is done */
    HSDR_FINISH_MORE,            /* more output remains */
    HSDR_FINISH_ERROR_NULL = -1, /* NULL arguments */
} HSD_finish_res;

#define HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(_)                                \
    HEATSHRINK_STATIC_INPUT_BUFFER_SIZE
#define HEATSHRINK_DECODER_WINDOW_BITS(_) (HEATSHRINK_STATIC_WINDOW_BITS)
#define HEATSHRINK_DECODER_LOOKAHEAD_BITS(BUF)                                 \
    (HEATSHRINK_STATIC_LOOKAHEAD_BITS)

typedef struct {
    uint16_t input_size;   /* bytes in input buffer */
    uint16_t input_index;  /* offset to next unprocessed input byte */
    uint16_t output_count; /* how many bytes to output */
    uint16_t output_index; /* index for bytes to output */
    uint16_t head_index;   /* head of window buffer */
    uint8_t state;         /* current state machine node */
    uint8_t current_byte;  /* current byte of input */
    uint8_t bit_index;     /* current bit index */

    /* Input buffer, then expansion window buffer */
    uint8_t buffers[(1 << HEATSHRINK_DECODER_WINDOW_BITS(_)) +
                    HEATSHRINK_DECODER_INPUT_BUFFER_SIZE(_)];
} heatshrink_decoder;

#ifdef __cplusplus
} // extern "C"
#endif

#endif
