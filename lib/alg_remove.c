#include <bpak/bpak.h>
#include <bpak/alg.h>

int bpak_alg_remove_init(struct bpak_alg_instance *ins,
                            struct bpak_io *in,
                            struct bpak_io *out,
                            struct bpak_io *origin)
{
    ins->output_size = 0;
    return BPAK_OK;
}

int bpak_alg_remove_process(struct bpak_alg_instance *ins)
{
    if (ins->done)
        return BPAK_OK;

    ins->done = true;

    return BPAK_OK;
}

static const struct bpak_alg alg_remove =
{
    .id = 0x57004cd0, /* id("remove-data") */
    .name = "remove-data",
    .on_init = bpak_alg_remove_init,
    .on_process = bpak_alg_remove_process,
    .state_size = 0,
};

int bpak_alg_remove_register(void)
{
    return bpak_alg_register(&alg_remove);
}
