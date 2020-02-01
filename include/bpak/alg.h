#ifndef INCLUDE_BPAK_ALG_H_
#define INCLUDE_BPAK_ALG_H_

#include <bpak/bpak.h>
#include <bpak/io.h>

#define __bpak_alg_tbl __attribute__ ((used, section("bpak_alg_tbl")))

#define BPAK_ALG(__alg_name) __bpak_alg_tbl \
            const struct bpak_alg __alg__##__alg_name##__ =

struct bpak_alg;
struct bpak_alg_instance;

typedef int (*bpak_alg_free_t)(struct bpak_alg_instance *ins);

typedef int (*bpak_alg_init_t)(struct bpak_alg_instance *ins,
                                    struct bpak_io *in,
                                    struct bpak_io *out,
                                    struct bpak_io *origin);

typedef int (*bpak_alg_process_t)(struct bpak_alg_instance *ins);

struct bpak_alg
{
    uint32_t id;
    uint32_t block_size;
    uint32_t parameter;
    bpak_alg_free_t on_free;
    bpak_alg_init_t on_init;
    bpak_alg_process_t on_process;
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
};

int bpak_alg_init(struct bpak_alg_instance *ins, uint32_t id,
                    struct bpak_part_header *part,
                    struct bpak_header *header,
                    uint8_t *state,
                    size_t size,
                    struct bpak_io *in,
                    struct bpak_io *out,
                    struct bpak_io *origin);

int bpak_alg_free(struct bpak_alg_instance *ins);
int bpak_alg_process(struct bpak_alg_instance *ins);

bool bpak_alg_done(struct bpak_alg_instance *ins);
size_t bpak_alg_output_size(struct bpak_alg_instance *ins);
int bpak_alg_get(uint32_t alg_id, struct bpak_alg **alg);

struct bpak_alg * bpak_alg_tbl_start(void);
struct bpak_alg * bpak_alg_tbl_end(void);

#endif  // INCLUDE_BPAK_ALG_H_
