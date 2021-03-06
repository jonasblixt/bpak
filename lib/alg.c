#include <string.h>
#include <bpak/bpak.h>
#include <bpak/alg.h>

#define BPAK_MAX_ALGS 64

static struct bpak_alg *__algs[BPAK_MAX_ALGS];

int bpak_alg_init(struct bpak_alg_instance *ins, uint32_t id,
                    struct bpak_part_header *part,
                    struct bpak_header *header,
                    uint8_t *state,
                    size_t size,
                    struct bpak_io *in,
                    struct bpak_io *out,
                    struct bpak_io *origin,
                    enum bpak_header_pos origin_header_pos,
                    enum bpak_header_pos out_header_pos)
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
    ins->origin_header_pos = origin_header_pos;
    ins->out_header_pos = out_header_pos;

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

bool bpak_alg_needs_more_data(struct bpak_alg_instance *ins)
{
    if (ins->alg->on_needs_more_data)
        return ins->alg->on_needs_more_data(ins);
    else
        return false;
}

int bpak_alg_process(struct bpak_alg_instance *ins)
{
    return ins->alg->on_process(ins);
}

int bpak_alg_get(uint32_t alg_id, struct bpak_alg **alg)
{
    for (int i = 0; i < BPAK_MAX_ALGS; i++)
    {
        if (!__algs[i])
            break;

        if (__algs[i]->id == alg_id)
        {
            (*alg) = __algs[i];
            return BPAK_OK;
        }
    }

    (*alg) = NULL;

    return -BPAK_FAILED;
}

int bpak_alg_register(const struct bpak_alg *alg)
{
    for (int i = 0; i < BPAK_MAX_ALGS; i++)
    {
        if (!__algs[i])
        {
            __algs[i] = (struct bpak_alg *) alg;
            return BPAK_OK;
        }
    }

    return -BPAK_FAILED;
}

