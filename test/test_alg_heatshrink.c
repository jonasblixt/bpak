#include <stdint.h>
#include <ctype.h>

#include "heatshrink/heatshrink_encoder.h"
#include "heatshrink/heatshrink_decoder.h"

#include "nala.h"

#if HEATSHRINK_DYNAMIC_ALLOC
#error HEATSHRINK_DYNAMIC_ALLOC must be false for static allocation test suite.
#endif


/* The majority of the tests are in test_heatshrink_dynamic, because that allows
 * instantiating encoders/decoders with different settings at run-time. */

static heatshrink_encoder hse;
static heatshrink_decoder hsd;

static void fill_with_pseudorandom_letters(uint8_t *buf, uint16_t size, uint32_t seed) {
    uint64_t rn = 9223372036854775783; /* prime under 2^64 */
    for (int i=0; i<size; i++) {
        rn = rn*seed + seed;
        buf[i] = (rn % 26) + 'a';
    }
}

static void dump_buf(char *name, uint8_t *buf, uint16_t count) {
    for (int i=0; i<count; i++) {
        uint8_t c = (uint8_t)buf[i];
        printf("%s %d: 0x%02x ('%c')\n", name, i, c, isprint(c) ? c : '.');
    }
}

static int compress_and_expand_and_check(uint8_t *input, uint32_t input_size, int log_lvl) {
    heatshrink_encoder_reset(&hse);
    heatshrink_decoder_reset(&hsd);
    size_t comp_sz = input_size + (input_size/2) + 4;
    size_t decomp_sz = input_size + (input_size/2) + 4;
    uint8_t *comp = malloc(comp_sz);
    uint8_t *decomp = malloc(decomp_sz);
    ASSERT(comp != NULL);
    ASSERT(decomp != NULL);
    memset(comp, 0, comp_sz);
    memset(decomp, 0, decomp_sz);

    size_t count = 0;

    if (log_lvl > 1) {
        printf("\n^^ COMPRESSING\n");
        dump_buf("input", input, input_size);
    }

    uint32_t sunk = 0;
    uint32_t polled = 0;
    while (sunk < input_size) {
        ASSERT(heatshrink_encoder_sink(&hse, &input[sunk], input_size - sunk, &count) >= 0);
        sunk += count;
        if (log_lvl > 1) printf("^^ sunk %zd\n", count);
        if (sunk == input_size) {
            ASSERT_EQ(HSER_FINISH_MORE, heatshrink_encoder_finish(&hse));
        }

        HSE_poll_res pres;
        do {                    /* "turn the crank" */
            pres = heatshrink_encoder_poll(&hse, &comp[polled], comp_sz - polled, &count);
            ASSERT(pres >= 0);
            polled += count;
            if (log_lvl > 1) printf("^^ polled %zd\n", count);
        } while (pres == HSER_POLL_MORE);
        ASSERT_EQ(HSER_POLL_EMPTY, pres);
        ASSERT(polled < comp_sz);
        if (sunk == input_size) {
            ASSERT_EQ(HSER_FINISH_DONE, heatshrink_encoder_finish(&hse));
        }
    }
    if (log_lvl > 0) printf("in: %u compressed: %u ", input_size, polled);
    uint32_t compressed_size = polled;
    sunk = 0;
    polled = 0;
    
    if (log_lvl > 1) {
        printf("\n^^ DECOMPRESSING\n");
        dump_buf("comp", comp, compressed_size);
    }
    while (sunk < compressed_size) {
        ASSERT(heatshrink_decoder_sink(&hsd, &comp[sunk], compressed_size - sunk, &count) >= 0);
        sunk += count;
        if (log_lvl > 1) printf("^^ sunk %zd\n", count);
        if (sunk == compressed_size) {
            ASSERT_EQ(HSDR_FINISH_MORE, heatshrink_decoder_finish(&hsd));
        }

        HSD_poll_res pres;
        do {
            pres = heatshrink_decoder_poll(&hsd, &decomp[polled],
                decomp_sz - polled, &count);
            ASSERT(pres >= 0);
            polled += count;
            if (log_lvl > 1) printf("^^ polled %zd\n", count);
        } while (pres == HSDR_POLL_MORE);
        ASSERT_EQ(HSDR_POLL_EMPTY, pres);
        if (sunk == compressed_size) {
            HSD_finish_res fres = heatshrink_decoder_finish(&hsd);
            ASSERT_EQ(HSDR_FINISH_DONE, fres);
        }

        ASSERT(polled <= input_size);
    }
    if (log_lvl > 0) printf("decompressed: %u\n", polled);
    ASSERT(polled == input_size);

    if (log_lvl > 1) dump_buf("decomp", decomp, polled);
    for (size_t i=0; i<input_size; i++) {
        if (input[i] != decomp[i]) {
            printf("*** mismatch at %zd\n", i);
            if (0) {
                for (size_t j=0; j<=/*i*/ input_size; j++) {
                    printf("in[%zd] == 0x%02x ('%c') => out[%zd] == 0x%02x ('%c')\n",
                        j, input[j], isprint(input[j]) ? input[j] : '.',
                        j, decomp[j], isprint(decomp[j]) ? decomp[j] : '.');
                }
            }
        }
        ASSERT_EQ(input[i], decomp[i]);
    }
    free(comp);
    free(decomp);
    return 0;
}


TEST(heatshrink)
{
    int rc;
    uint8_t input[1024*8];

    for (uint32_t size=1; size < sizeof(input); size <<= 1)
    {
            for (uint32_t seed=1; seed<=100; seed++)
            {
                fill_with_pseudorandom_letters(input, size, seed);
                rc = compress_and_expand_and_check(input, size, 0);

                ASSERT_EQ(rc, 0);
            }
    }
}

