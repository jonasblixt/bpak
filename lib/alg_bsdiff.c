#include <bpak/bpak.h>
#include <bpak/alg.h>

static int bpak_alg_bsdiff_init(struct bpak_alg_instance *ins,
                                struct bpak_io *in,
                                struct bpak_io *out,
                                struct bpak_io *origin)
{
    ins->done = true;
    return -BPAK_FAILED;
}

static int bpak_alg_bsdiff_process(struct bpak_alg_instance *ins)
{
    return -BPAK_FAILED;
}

BPAK_ALG(bsdiff)
{
    .id = 0x9f7aacf9, /* id("bsdiff") */
    .name = "bsdiff",
    .on_init = bpak_alg_bsdiff_init,
    .on_process = bpak_alg_bsdiff_process,
    .state_size = 0,
};
