#include <bpak/bpak.h>
#include <bpak/alg.h>

static int bpak_alg_bspatch_init(struct bpak_alg_instance *ins,
                                struct bpak_io *in,
                                struct bpak_io *out,
                                struct bpak_io *origin)
{
    ins->done = true;
    return -BPAK_FAILED;
}

static int bpak_alg_bspatch_process(struct bpak_alg_instance *ins)
{
    return -BPAK_FAILED;
}

BPAK_ALG(bspatch)
{
    .id = 0xb5964388, /* id("bspatch") */
    .name = "bspatch",
    .on_init = bpak_alg_bspatch_init,
    .on_process = bpak_alg_bspatch_process,
    .state_size = 0,
};
