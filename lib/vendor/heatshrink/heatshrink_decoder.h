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

/* The functions of the decoder. The public bpak/heatshrink_decoder.h has
 * the decoder state that struct bpak_bspatch_context embeds. The library is
 * compiled with definitions that prefix the functions with bpak_, see
 * bpak-vendor-names in lib/CMakeLists.txt. */

#ifndef HEATSHRINK_DECODER_FUNCTIONS_H
#define HEATSHRINK_DECODER_FUNCTIONS_H

#include <bpak/heatshrink_decoder.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reset a decoder. */
void heatshrink_decoder_reset(heatshrink_decoder *hsd);

/* Sink at most SIZE bytes from IN_BUF into the decoder. *INPUT_SIZE is set to
 * indicate how many bytes were actually sunk (in case a buffer was filled). */
HSD_sink_res heatshrink_decoder_sink(heatshrink_decoder *hsd, uint8_t *in_buf,
                                     size_t size, size_t *input_size);

/* Poll for output from the decoder, copying at most OUT_BUF_SIZE bytes into
 * OUT_BUF (setting *OUTPUT_SIZE to the actual amount copied). */
HSD_poll_res heatshrink_decoder_poll(heatshrink_decoder *hsd, uint8_t *out_buf,
                                     size_t out_buf_size, size_t *output_size);

/* Notify the dencoder that the input stream is finished.
 * If the return value is HSDR_FINISH_MORE, there is still more output, so
 * call heatshrink_decoder_poll and repeat. */
HSD_finish_res heatshrink_decoder_finish(heatshrink_decoder *hsd);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
