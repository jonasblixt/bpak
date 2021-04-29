#ifndef INCLUDE_BPAK_ALG_H_
#define INCLUDE_BPAK_ALG_H_

#include <bpak/bpak.h>
#include <bpak/io.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_alg;
struct bpak_alg_instance;

typedef int (*bpak_alg_free_t)(struct bpak_alg_instance *ins);

typedef bool (*bpak_alg_needs_more_data_t)(struct bpak_alg_instance *ins);
typedef int (*bpak_alg_init_t)(struct bpak_alg_instance *ins,
                                    struct bpak_io *in,
                                    struct bpak_io *out,
                                    struct bpak_io *origin);

typedef int (*bpak_alg_process_t)(struct bpak_alg_instance *ins);

typedef int (*bpak_alg_print_t)(struct bpak_alg_instance *ins,
                                int verbosity,
                                const char *fmt, ...);

struct bpak_alg
{
    uint32_t id;
    uint32_t block_size;
    uint32_t parameter;
    bpak_alg_free_t on_free;
    bpak_alg_init_t on_init;
    bpak_alg_process_t on_process;
    bpak_alg_needs_more_data_t on_needs_more_data;
    size_t state_size;
    const char *name;
};

struct bpak_alg_instance
{
    const struct bpak_alg *alg;
    struct bpak_part_header *part;
    struct bpak_header *header;
    bool done;
    void *state;
    uint64_t output_size;
    enum bpak_header_pos origin_header_pos;
    enum bpak_header_pos out_header_pos;
};

int bpak_alg_init(struct bpak_alg_instance *ins, uint32_t id,
                    struct bpak_part_header *part,
                    struct bpak_header *header,
                    uint8_t *state,
                    size_t size,
                    struct bpak_io *in,
                    struct bpak_io *out,
                    struct bpak_io *origin,
                    enum bpak_header_pos origin_header_pos,
                    enum bpak_header_pos out_header_pos);

int bpak_alg_free(struct bpak_alg_instance *ins);
int bpak_alg_process(struct bpak_alg_instance *ins);

bool bpak_alg_done(struct bpak_alg_instance *ins);
size_t bpak_alg_output_size(struct bpak_alg_instance *ins);
bool bpak_alg_needs_more_data(struct bpak_alg_instance *ins);
int bpak_alg_get(uint32_t alg_id, struct bpak_alg **alg);
int bpak_alg_register(const struct bpak_alg *alg);


int bpak_alg_remove_register(void);
int bpak_alg_bsdiff_register(void);
int bpak_alg_bspatch_register(void);
int bpak_alg_heatshrink_register(void);
int bpak_alg_merkle_register(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_ALG_H_
