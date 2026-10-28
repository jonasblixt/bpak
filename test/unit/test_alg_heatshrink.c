#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "heatshrink/heatshrink_encoder.h"
#include <bpak/heatshrink_decoder.h>

#include "test_helpers.h"

#if HEATSHRINK_DYNAMIC_ALLOC
#error HEATSHRINK_DYNAMIC_ALLOC must be false for static allocation test suite.
#endif

static heatshrink_encoder hse;
static heatshrink_decoder hsd;

static void fill_with_pseudorandom_letters(uint8_t *buf, uint16_t size,
                                           uint32_t seed)
{
    uint64_t rn = 9223372036854775783; /* prime under 2^64 */
    for (int i = 0; i < size; i++) {
        rn = rn * seed + seed;
        buf[i] = (rn % 26) + 'a';
    }
}

static void compress_and_expand_and_check(uint8_t *input, uint32_t input_size)
{
    heatshrink_encoder_reset(&hse);
    heatshrink_decoder_reset(&hsd);
    size_t comp_sz = input_size + (input_size / 2) + 4;
    size_t decomp_sz = input_size + (input_size / 2) + 4;
    uint8_t *comp = calloc(1, comp_sz);
    uint8_t *decomp = calloc(1, decomp_sz);
    assert_non_null(comp);
    assert_non_null(decomp);

    size_t count = 0;
    uint32_t sunk = 0;
    uint32_t polled = 0;

    while (sunk < input_size) {
        assert_true(heatshrink_encoder_sink(&hse,
                                            &input[sunk],
                                            input_size - sunk,
                                            &count) >= 0);
        sunk += count;
        if (sunk == input_size) {
            assert_int_equal(heatshrink_encoder_finish(&hse),
                             HSER_FINISH_MORE);
        }

        HSE_poll_res pres;
        do { /* "turn the crank" */
            pres = heatshrink_encoder_poll(&hse,
                                           &comp[polled],
                                           comp_sz - polled,
                                           &count);
            assert_true(pres >= 0);
            polled += count;
        } while (pres == HSER_POLL_MORE);
        assert_int_equal(pres, HSER_POLL_EMPTY);
        assert_true(polled < comp_sz);
        if (sunk == input_size) {
            assert_int_equal(heatshrink_encoder_finish(&hse),
                             HSER_FINISH_DONE);
        }
    }

    uint32_t compressed_size = polled;
    sunk = 0;
    polled = 0;

    while (sunk < compressed_size) {
        assert_true(heatshrink_decoder_sink(&hsd,
                                            &comp[sunk],
                                            compressed_size - sunk,
                                            &count) >= 0);
        sunk += count;
        if (sunk == compressed_size) {
            assert_int_equal(heatshrink_decoder_finish(&hsd),
                             HSDR_FINISH_MORE);
        }

        HSD_poll_res pres;
        do {
            pres = heatshrink_decoder_poll(&hsd,
                                           &decomp[polled],
                                           decomp_sz - polled,
                                           &count);
            assert_true(pres >= 0);
            polled += count;
        } while (pres == HSDR_POLL_MORE);
        assert_int_equal(pres, HSDR_POLL_EMPTY);
        if (sunk == compressed_size) {
            assert_int_equal(heatshrink_decoder_finish(&hsd),
                             HSDR_FINISH_DONE);
        }

        assert_true(polled <= input_size);
    }

    assert_int_equal(polled, input_size);
    assert_memory_equal(input, decomp, input_size);

    free(comp);
    free(decomp);
}

static void test_heatshrink_roundtrip(void **state)
{
    (void)state;
    uint8_t input[1024 * 8];

    for (uint32_t size = 1; size < sizeof(input); size <<= 1) {
        for (uint32_t seed = 1; seed <= 100; seed++) {
            fill_with_pseudorandom_letters(input, size, seed);
            compress_and_expand_and_check(input, size);
        }
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_heatshrink_roundtrip),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
