#include <string.h>
#include <bpak/bpak.h>
#include <bpak/alg.h>

extern struct bpak_alg __start_bpak_alg_tbl[], __stop_bpak_alg_tbl[];


int bpak_alg_init(struct bpak_alg_instance *ins, uint32_t id,
                    struct bpak_part_header *part,
                    struct bpak_header *header,
                    uint8_t *state,
                    size_t size,
                    struct bpak_io *in,
                    struct bpak_io *out,
                    struct bpak_io *origin)
{
    struct bpak_alg *alg = NULL;
    int rc;

    memset(ins, 0, sizeof(*ins));

    rc = bpak_alg_get(id, &alg);

    if (rc != BPAK_OK)
        return rc;

    if (size < alg->state_size)
        return -BPAK_FAILED;

    ins->alg = alg;
    ins->state = state;
    ins->part = part;
    ins->header = header;

    memset(ins->state, 0, alg->state_size);

    if (alg->on_init)
        return alg->on_init(ins, in, out, origin);
    else
        return BPAK_OK;
}

size_t bpak_alg_output_size(struct bpak_alg_instance *ins)
{
    return ins->output_size;
}

bool bpak_alg_done(struct bpak_alg_instance *ins)
{
    return ins->done;
}

int bpak_alg_free(struct bpak_alg_instance *ins)
{
    if (ins->alg->on_free)
        return ins->alg->on_free(ins);
    else
        return BPAK_OK;
}

int bpak_alg_process(struct bpak_alg_instance *ins)
{
    return ins->alg->on_process(ins);
}

struct bpak_alg * bpak_alg_tbl_start(void)
{
    return __start_bpak_alg_tbl;
}

struct bpak_alg *bpak_alg_tbl_end(void)
{
    return __stop_bpak_alg_tbl;
}

int bpak_alg_get(uint32_t alg_id, struct bpak_alg **alg)
{


    uint8_t *p = (uint8_t *) bpak_alg_tbl_start();
    uint8_t *e = (uint8_t *) bpak_alg_tbl_end();

    while (p < e)
    {
        struct bpak_alg *a = (struct bpak_alg *) p;

        if (a->id == alg_id)
        {
            (*alg) = a;
            return BPAK_OK;
        }

        p += sizeof(struct bpak_alg) + (32 - sizeof(struct bpak_alg) % 32);
    }

    (*alg) = NULL;

    return -BPAK_FAILED;
}
