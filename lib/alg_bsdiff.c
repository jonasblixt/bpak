#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpak/bpak.h>
#include <bpak/alg.h>
#include <bpak/file.h>
#include <bpak/pipe.h>

#include "sais.h"

struct bpak_bsdiff_private
{
    size_t old_size;
    size_t new_size;
    uint8_t *old;
    uint8_t *new;
    uint64_t *suffix_array;
    size_t suffix_array_size;
    int suffix_array_fd;
    int64_t scan;
    int64_t len;
    int64_t pos;
    int64_t last_scan;
    int64_t last_pos;
    int64_t last_offset;
    int64_t scsc;
    uint8_t buffer[4096];
    struct bpak_io *compressor_pipe;
    uint8_t compressor_buffer[1024*32];
    struct bpak_alg_instance compressor;
    char suffix_fn[64];
};

#define BSDIFF_PRIVATE(__ins) ((struct bpak_bsdiff_private *) __ins->state)
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static int32_t matchlen(uint8_t *from_p,
                        int64_t from_size,
                        uint8_t *to_p,
                        int64_t to_size)
{
    int64_t i;

    for (i = 0; i < MIN(from_size, to_size); i++)
    {
        if (from_p[i] != to_p[i])
        {
            break;
        }
    }

    return (i);
}

static int64_t search(int64_t *sa_p,
                      uint8_t *from_p,
                      int64_t from_size,
                      uint8_t *to_p,
                      int64_t to_size,
                      int64_t from_begin,
                      int64_t from_end,
                      int64_t *pos_p)
{
    int64_t x;
    int64_t y;

    if (from_end - from_begin < 2)
    {
        x = matchlen(from_p + sa_p[from_begin],
                     from_size - sa_p[from_begin],
                     to_p,
                     to_size);
        y = matchlen(from_p + sa_p[from_end],
                     from_size - sa_p[from_end],
                     to_p,
                     to_size);

        if (x > y)
        {
            *pos_p = sa_p[from_begin];

            return (x);
        }
        else
        {
            *pos_p = sa_p[from_end];

            return (y);
        }
    }

    x = (from_begin + (from_end - from_begin) / 2);

    if (memcmp(from_p + sa_p[x], to_p, MIN(from_size - sa_p[x], to_size)) < 0)
    {
        return search(sa_p, from_p, from_size, to_p, to_size, x, from_end, pos_p);
    }
    else
    {
        return search(sa_p, from_p, from_size, to_p, to_size, from_begin, x, pos_p);
    }
}

static void offtout(int64_t x, uint8_t *buf)
{
	int64_t y;

	if(x<0) y=-x; else y=x;

	buf[0]=y%256;y-=buf[0];
	y=y/256;buf[1]=y%256;y-=buf[1];
	y=y/256;buf[2]=y%256;y-=buf[2];
	y=y/256;buf[3]=y%256;y-=buf[3];
	y=y/256;buf[4]=y%256;y-=buf[4];
	y=y/256;buf[5]=y%256;y-=buf[5];
	y=y/256;buf[6]=y%256;y-=buf[6];
	y=y/256;buf[7]=y%256;

	if(x<0) buf[7]|=0x80;
}

static int write_data(struct bpak_alg_instance *ins, uint8_t *bfr, size_t size)
{
    size_t data_to_write = size;
    size_t chunk = 0;
    int rc;
    int i = 0;
    struct bpak_bsdiff_private *p = BSDIFF_PRIVATE(ins);

    while (data_to_write)
    {
        chunk = (data_to_write > sizeof(p->buffer))? \
                                sizeof(p->buffer):data_to_write;

        for (int n = 0; n < chunk; n++)
        {
            p->buffer[n] = bfr[i];
            i++;
        }

        rc = bpak_io_write(p->compressor_pipe, p->buffer, chunk);

        if (rc != chunk)
        {
            rc = -BPAK_FAILED;
            printf("Error: Write error\n");
            return rc;
        }

        rc = bpak_alg_process(&p->compressor);

        if (rc != BPAK_OK)
        {
            printf("Error: compressor alg error\n");
            return rc;
        }

        data_to_write -= chunk;
    }

    return BPAK_OK;
}

static int write_diff_extra_and_adjustment(struct bpak_alg_instance *ins)
{
    int res;
    int64_t s;
    int64_t sf;
    int64_t diff_size;
    int64_t extra_pos;
    int64_t extra_size;
    int64_t sb;
    int64_t lenb;
    int64_t overlap;
    int64_t ss;
    int64_t lens;
    int64_t i;
    int64_t last_scan;
    int64_t last_pos;
    struct bpak_bsdiff_private *p = BSDIFF_PRIVATE(ins);

    last_scan = p->last_scan;
    last_pos = p->last_pos;
    s = 0;
    sf = 0;
    diff_size = 0;

    for (i = 0; (last_scan + i < p->scan) && (last_pos + i < p->old_size);)
    {
        if (p->old[last_pos + i] == p->new[last_scan + i])
        {
            s++;
        }

        i++;

        if (s * 2 - i > sf * 2 - diff_size)
        {
            sf = s;
            diff_size = i;
        }
    }

    lenb = 0;

    if (p->scan < p->new_size)
    {
        s = 0;
        sb = 0;

        for (i = 1; (p->scan >= last_scan + i) && (p->pos >= i); i++)
        {
            if (p->old[p->pos - i] == p->new[p->scan - i])
            {
                s++;
            }

            if (s * 2 - i > sb * 2 - lenb)
            {
                sb = s;
                lenb = i;
            }
        }
    }

    overlap = (last_scan + diff_size) - (p->scan - lenb);

    if (overlap > 0)
    {
        s = 0;
        ss = 0;
        lens = 0;

        for (i = 0; i < overlap; i++)
        {
            if (p->new[last_scan + diff_size - overlap + i]
                == p->old[last_pos + diff_size - overlap + i])
            {
                s++;
            }

            if (p->new[p->scan - lenb + i] == p->old[p->pos - lenb + i])
            {
                s--;
            }

            if (s > ss)
            {
                ss = s;
                lens = (i + 1);
            }
        }

        diff_size += (lens - overlap);
        lenb -= lens;
    }

    uint64_t chunk = 0;

    extra_pos = (last_scan + diff_size);
    extra_size = (p->scan - lenb - extra_pos);

    /* Write control data*/
    printf("diff: %10li %10li %10li\n", diff_size, extra_size,
                (p->pos - lenb) - (last_pos + diff_size));

    offtout(diff_size, p->buffer);

    res = write_data(ins, p->buffer, 8);

    if (res != BPAK_OK)
        return res;

    offtout(extra_size, p->buffer);
    res = write_data(ins, p->buffer, 8);

    if (res != BPAK_OK)
        return res;

    /* Adjustment. */
    offtout((p->pos - lenb) - (last_pos + diff_size), p->buffer);
    res = write_data(ins, p->buffer, 8);

    if (res != BPAK_OK)
        return res;

    /* Write diff data */
    uint64_t data_to_write = diff_size;

    i = 0;

    while (data_to_write)
    {
        chunk = (data_to_write > sizeof(p->buffer))? \
                                sizeof(p->buffer):data_to_write;

        for (int n = 0; n < chunk; n++)
        {
            p->buffer[n] = (p->new[last_scan + i] - p->old[last_pos + i]);
            i++;
        }

        res = bpak_io_write(p->compressor_pipe, p->buffer, chunk);

        if (res != chunk)
        {
            res = -BPAK_FAILED;
            printf("Error: Write error\n");
            return res;
        }

        res = bpak_alg_process(&p->compressor);

        if (res != BPAK_OK)
        {
            printf("Error: compressor alg error\n");
            return res;
        }

        data_to_write -= chunk;
    }

    /* Extra data. */
    if (extra_size)
    {
        res = write_data(ins, &p->new[extra_pos], extra_size);

        if (res != BPAK_OK)
            return res;
    }

    p->last_scan = (p->scan - lenb);
    p->last_pos = (p->pos - lenb);
    p->last_offset = (p->pos - p->scan);

    return (0);
}

static int bpak_alg_bsdiff_init(struct bpak_alg_instance *ins,
                                struct bpak_io *in,
                                struct bpak_io *out,
                                struct bpak_io *origin)
{
    struct bpak_bsdiff_private *priv = BSDIFF_PRIVATE(ins);
    struct bpak_header h;
    struct bpak_part_header *p = NULL;
    int rc;

    memset(priv, 0, sizeof(*priv));

    printf("bsdiff init, part: %x, %li, %li\n", ins->part->id,
                        bpak_part_size(ins->part),
                        bpak_part_offset(ins->header, ins->part));

    rc = bpak_io_read(origin, &h, sizeof(h));

    if (rc != sizeof(h))
        return -BPAK_FAILED;

    rc = bpak_valid_header(&h);

    if (rc != BPAK_OK)
        return rc;

    printf("Read origin header\n");
    rc = bpak_get_part(&h, ins->part->id, &p);

    if (rc != BPAK_OK)
        return rc;

    printf("Found origin part, %li %li\n", bpak_part_size(p),
                                        bpak_part_offset(&h, p));
    priv->old_size = bpak_part_size(p);
    priv->old = mmap(NULL, priv->old_size, PROT_READ,
                        MAP_SHARED, bpak_io_file_to_fd(origin),
                        bpak_part_offset(&h, p));

    if (!priv->old)
        return -BPAK_FAILED;


    priv->new_size = bpak_part_size(ins->part);
    priv->new = mmap(NULL, priv->new_size, PROT_READ,
                        MAP_SHARED, bpak_io_file_to_fd(in),
                        bpak_part_offset(ins->header, ins->part));
    if (!priv->new)
    {
        rc = -BPAK_FAILED;
        goto err_munmap_old;
    }

    snprintf(priv->suffix_fn, sizeof(priv->suffix_fn),
                "/tmp/.bpak_tmp_%x", rand());

    priv->suffix_array_fd = \
            open(priv->suffix_fn, O_RDWR | O_TRUNC | O_CREAT, 0600);

    if (priv->suffix_array_fd < 0)
    {
        rc = -BPAK_FAILED;
        goto err_munmap_new;
    }

    rc = bpak_io_init_pipe(&priv->compressor_pipe);

    if (rc != BPAK_OK)
    {
        goto err_close_fd;
    }

    rc = bpak_alg_init(&priv->compressor, ins->alg->parameter,
                        NULL, NULL,
                        priv->compressor_buffer, sizeof(priv->compressor_buffer),
                        priv->compressor_pipe, out, NULL);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not initialize compressor\n");
        return rc;
    }

    priv->suffix_array_size = priv->old_size * sizeof(int64_t);
    ftruncate(priv->suffix_array_fd, priv->suffix_array_size);

    priv->suffix_array = mmap(NULL, priv->suffix_array_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED,
                                priv->suffix_array_fd, 0);

    if (!priv->suffix_array)
    {
        rc = -BPAK_FAILED;
        goto err_close_io;
    }

    rc = sais((uint8_t *)priv->old, priv->suffix_array, priv->old_size);

    if (rc != 0)
    {
        rc = -BPAK_FAILED;
        goto err_munmap_suffix;
    }

    return BPAK_OK;

err_munmap_suffix:
    munmap(priv->suffix_array, priv->suffix_array_size);
err_close_io:
    bpak_io_close(priv->compressor_pipe);
err_close_fd:
    close(priv->suffix_array_fd);
err_munmap_new:
    munmap(priv->new, priv->new_size);
err_munmap_old:
    munmap(priv->old, priv->old_size);
    return rc;
}

static int bpak_alg_bsdiff_free(struct bpak_alg_instance *ins)
{
    struct bpak_bsdiff_private *priv = BSDIFF_PRIVATE(ins);
    munmap(priv->old, priv->old_size);
    munmap(priv->new, priv->new_size);
    munmap(priv->suffix_array, priv->suffix_array_size);
    close(priv->suffix_array_fd);
    bpak_io_close(priv->compressor_pipe);
    remove(priv->suffix_fn);
    return BPAK_OK;
}

static int bpak_alg_bsdiff_process(struct bpak_alg_instance *ins)
{
    struct bpak_bsdiff_private *p = BSDIFF_PRIVATE(ins);
    int rc;


    if (p->scan >= p->new_size)
    {
        ins->done = true;

        while (!bpak_alg_done(&p->compressor))
        {
            rc = bpak_alg_process(&p->compressor);

            if (rc != BPAK_OK)
                return rc;
        }
        ins->output_size = p->compressor.output_size;

        return BPAK_OK;
    }

    int64_t from_score = 0;

    p->scan += p->len;

    for (int64_t scsc = p->scan; p->scan < p->new_size; p->scan++)
    {
        p->len = search(p->suffix_array,
                             p->old,
                             p->old_size,
                             p->new + p->scan,
                             p->new_size - p->scan,
                             0,
                             p->old_size,
                             &(p->pos));

        for (; scsc < p->scan + p->len; scsc++)
        {
            if ((scsc + p->last_offset < p->old_size)
                && (p->old[scsc + p->last_offset] == p->new[scsc]))
            {
                from_score++;
            }
        }

        if (((p->len == from_score) && (p->len != 0)) || (p->len > from_score + 8))
        {
            break;
        }

        if ((p->scan + p->last_offset < p->old_size)
            && (p->old[p->scan + p->last_offset] == p->new[p->scan]))
        {
            from_score--;
        }
    }

    if ((p->len != from_score) || (p->scan == p->new_size))
    {
        rc = write_diff_extra_and_adjustment(ins);

        if (rc != 0)
        {
            return -BPAK_FAILED;
        }
    }

    return BPAK_OK;
}

BPAK_ALG(bsdiff)
{
    .id = 0x9f7aacf9, /* id("bsdiff") */
    .name = "bsdiff",
    .parameter = 0xe31722a6, /* id("heatshrink-encode") */
    .on_init = bpak_alg_bsdiff_init,
    .on_free = bpak_alg_bsdiff_free,
    .on_process = bpak_alg_bsdiff_process,
    .state_size = sizeof(struct bpak_bsdiff_private),
};


BPAK_ALG(bsdiff_lz4)
{
    .id = 0x799dc2ee, /* id("bsdiff-lz4") */
    .name = "bsdiff-lz4",
    .parameter = 0xbd57d09a, /* id("lz4-encode") */
    .on_init = bpak_alg_bsdiff_init,
    .on_free = bpak_alg_bsdiff_free,
    .on_process = bpak_alg_bsdiff_process,
    .state_size = sizeof(struct bpak_bsdiff_private),
};
