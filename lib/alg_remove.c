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

BPAK_ALG(remove_data)
{
    .id = 0x57004cd0, /* id("remove-data") */
    .name = "remove-data",
    .on_init = bpak_alg_remove_init,
    .on_process = bpak_alg_remove_process,
    .state_size = 0,
};
