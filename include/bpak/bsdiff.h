#ifndef BPAK_BSDIFF_H
#define BPAK_BSDIFF_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <bpak/bpak.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_bsdiff_context
{
    int origin_fd;
    uint8_t *origin_data;
    size_t origin_length;
    int new_fd;
    uint8_t *new_data;
    size_t new_length;
    int64_t *suffix_array;
    size_t suffix_array_size;
    int64_t scan;
    int64_t len;
    int64_t pos;
    int64_t last_scan;
    int64_t last_pos;
    int64_t last_offset;
    int64_t scsc;
    char suffix_fn[64];
    bpak_io_t write_output;
    size_t output_pos;
    void *user_priv;
};


int bpak_bsdiff_init(struct bpak_bsdiff_context *ctx,
                      uint8_t *origin_data,
                      size_t origin_length,
                      uint8_t *new_data,
                      size_t new_length,
                      bpak_io_t write_output,
                      void *user_priv);

int bpak_bsdiff(struct bpak_bsdiff_context *ctx);

int bpak_bsdiff_free(struct bpak_bsdiff_context *ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
