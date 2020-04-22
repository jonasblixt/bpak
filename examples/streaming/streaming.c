#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <bpak/bpak.h>
#include <bpak/file.h>
#include <bpak/fifo.h>
#include <bpak/utils.h>
#include <bpak/alg.h>
#include <bpak/pkg.h>
#include <curl/curl.h>

static int epollFd;
static int timeout = -1;
static struct pollfd pollfd;

enum states
{
    STATE_LOAD_HEADER,
    STATE_PROCESS_PREPARE,
    STATE_PROCESS_PART,
    STATE_PROCESS_NEXT_PART,
    STATE_DONE,
    STATE_FAILED,
};

struct stream_state
{
    struct bpak_header header;
    struct bpak_header origin_header;
    struct bpak_header output_header;
    struct bpak_part_header *part;
    struct bpak_transport_meta *transport_meta;
    struct bpak_io *fifo;
    struct bpak_io *origin;
    struct bpak_io *out;
    struct bpak_alg *alg;
    struct bpak_alg_instance alg_ins;
    uint64_t stream_pos;
    size_t bytes_remaining;
    enum states state;
    uint8_t chunk_buffer[4096];
    size_t chunk_buffer_size;
    uint8_t state_buffer[1024*64];
    CURLM *multi;
};


int bpak_printf(int verbosity, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("-- ");
    vprintf(fmt, args);
    va_end(args);
    return BPAK_OK;
}


static void error(const char* string)
{
  perror(string);
  exit(1);
}

static int process_update(struct stream_state *ss)
{
    int rc;
    size_t read_data = 0;
    size_t chunk_sz = 0;

process_more:

    switch (ss->state)
    {
        case STATE_LOAD_HEADER:
        {
            /* Wait for fifo to fill up first */
            if (bpak_fifo_available_data(ss->fifo) < sizeof(ss->header))
                break;

            rc = bpak_io_read(ss->fifo, &(ss->header), sizeof(ss->header));

            if (rc != sizeof(ss->header))
            {
                printf("Error: Fifo read error\n");
                ss->state = STATE_FAILED;
                break;
            }

            rc = bpak_valid_header(&ss->header);

            if (rc != BPAK_OK)
            {
                printf("Error: Invalid header\n");
                ss->state = STATE_FAILED;
                break;
            }

            printf("Valid bpak header:\n");
            bpak_foreach_meta(&ss->header, m)
            {
                if (!m->id)
                    break;

                printf("Meta %x, %i, %i\n", m->id, m->size, m->offset);
            }

            printf("Opening origin stream...\n");
            rc = bpak_io_init_file(&ss->origin, "vA.bpak", "r");

            if (rc != BPAK_OK)
            {
                printf("Error: Could not open origin file\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

            rc = bpak_io_seek(ss->origin, 0, BPAK_IO_SEEK_SET);

            if (rc != BPAK_OK)
            {
                printf("Error: origin seek\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

            size_t read_bytes = bpak_io_read(ss->origin, &ss->origin_header,
                                                sizeof(ss->origin_header));

            if (read_bytes != sizeof(ss->origin_header))
            {
                printf("Error: Could not read origin header\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

            rc = bpak_valid_header(&ss->origin_header);

            if (rc != BPAK_OK)
            {
                printf("Error: Invalid origin header\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

            printf("Origin header OK\n");

            rc = bpak_io_init_file(&ss->out, "out.bpak", "w+");

            if (rc != BPAK_OK)
            {
                printf("Error: Could not open ouput file\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

            printf("Opened output stream 'out.bpak'\n");


            printf("Preparing output header\n");
            memcpy(&ss->output_header, &ss->header, sizeof(ss->header));

            /* Clear transport flag */
            bpak_foreach_part(&ss->output_header, p)
            {
                if (!p->id)
                    break;
                if (p->flags & BPAK_FLAG_TRANSPORT)
                {
                    p->flags &= ~BPAK_FLAG_TRANSPORT;
                    p->transport_size = 0;
                }
            }

            size_t written = bpak_io_write(ss->out, &ss->output_header,
                                            sizeof(ss->output_header));

            if (written != sizeof(ss->output_header))
            {
                printf("Error: Could not write output header\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

            ss->part = ss->header.parts;
            ss->state = STATE_PROCESS_PREPARE;

            if (bpak_fifo_available_data(ss->fifo))
                goto process_more;
        }
        break;
        case STATE_PROCESS_PREPARE:
        {
            printf("Processing part: %x (%li)\n", ss->part->id,
                        bpak_part_size(ss->part));
            ss->state = STATE_PROCESS_PART;
            ss->bytes_remaining = bpak_part_size(ss->part);

            rc = bpak_get_meta_with_ref(&ss->header, 0x2d44bbfb, ss->part->id,
                                (void **) &ss->transport_meta);


            if (rc == BPAK_OK)
            {
                printf("Transport meta: %x\n", ss->transport_meta->alg_id_decode);

                rc = bpak_alg_get(ss->transport_meta->alg_id_decode, &ss->alg);

                printf("Initializing alg: %x (%p)\n",
                            ss->transport_meta->alg_id_decode, ss->alg);

                if (rc != BPAK_OK || !ss->alg)
                {
                    printf("Error: Unknown algorithm: %8.8x\n",
                                ss->transport_meta->alg_id_decode);
                    ss->state = STATE_FAILED;
                    goto process_more;
                }

                bpak_io_seek(ss->out, 4096, BPAK_IO_SEEK_SET);
                bpak_io_seek(ss->origin, 0, BPAK_IO_SEEK_SET);

                rc = bpak_alg_init(&ss->alg_ins,
                                   ss->transport_meta->alg_id_decode,
                                   ss->part,
                                   &ss->header,
                                   ss->state_buffer,
                                   sizeof(ss->state_buffer),
                                   ss->fifo,
                                   ss->out,
                                   ss->origin);

                if (rc != BPAK_OK)
                {
                    bpak_printf(0, "Error: Could not initialize algorithm %8.8x\n",
                            ss->transport_meta->alg_id_decode);

                    ss->state = STATE_FAILED;
                    goto process_more;
                }

                printf("Alg initialized\n");
            }
            else
            {
                printf("Part not transport coded\n");
                ss->transport_meta = NULL;
                ss->alg = NULL;
            }


            goto process_more;
        }
        break;
        case STATE_PROCESS_PART:
        {
  /*          printf("P1 %li %i\n", bpak_fifo_available_data(ss->fifo),
                                     bpak_alg_done(&ss->alg_ins));
*/
            rc = bpak_alg_process(&ss->alg_ins);

            if (rc != BPAK_OK)
            {
                printf("Error: processing failed\n");
                ss->state = STATE_FAILED;
                goto process_more;
            }

 /*           printf("P2 %li %i\n", bpak_fifo_available_data(ss->fifo),
                                     bpak_alg_done(&ss->alg_ins));
*/


            if (bpak_alg_done(&ss->alg_ins))
            {
                printf("Done\n");
                ss->state = STATE_PROCESS_NEXT_PART;
                goto process_more;
            }

            if (bpak_fifo_available_data(ss->fifo))
            {
                goto process_more;
            }
        }
        break;
        case STATE_PROCESS_NEXT_PART:
        {

            while (!bpak_alg_done(&ss->alg_ins))
            {
                rc = bpak_alg_process(&ss->alg_ins);

                if (rc != BPAK_OK)
                {
                    printf("Error: processing failed\n");
                    ss->state = STATE_FAILED;
                    goto process_more;
                }
            }

            ss->part++;

            /* No more parts in this archive to process */
            if (!ss->part->id)
            {
                /* More data to process? */
                if (bpak_fifo_available_data(ss->fifo))
                {
                    printf("Read next header %li\n",
                                bpak_fifo_available_data(ss->fifo));
                    ss->state = STATE_LOAD_HEADER;
                }
                else
                {
                    printf("finishing up...\n");
                    ss->state = STATE_DONE;
                }
                goto process_more;
            }

            ss->state = STATE_PROCESS_PREPARE;
            goto process_more;
        }
        break;
        case STATE_DONE:
        {
            printf("Entered DONE state\n");
        }
        break;
        case STATE_FAILED:
        {
            printf("STATE_FAILED\n");
        }
        break;
        default:
        {
            printf("Unknown state %i\n", ss->state);
        }
        break;
    }
}

static size_t stream_cb(void *contents, size_t length, size_t nmemb,
                                  void *userp)
{
    size_t real_size = length * nmemb;
    struct stream_state *ss = (struct stream_state *) userp;
    int rc;

    printf("stream_cb: %zu\n", real_size);

    size_t written = bpak_io_write(ss->fifo, contents, real_size);

    //size_t written = bpak_io_write(ss->fifo, contents, 1);
    ss->stream_pos += written;

    process_update(ss);

    return written;
}

static int sock_cb(CURL* easy, curl_socket_t fd, int action, void* u, void* s)
{
    int rc;
    struct stream_state *ss = (struct stream_state *) s;
    const char *whatstr[]={ "none", "IN", "OUT", "INOUT", "REMOVE" };

    struct epoll_event event;
    event.events = 0;
    event.data.fd = fd;

    pollfd.fd = fd;
    pollfd.events = 0;
    pollfd.revents = 0;
    /* Remove fd */
    if (action == CURL_POLL_REMOVE)
    {
        printf(">>> %s: removing fd=%d\n", __func__, fd);

        assert(pollfd.fd == fd);
        pollfd.fd = -1;

        rc = epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, &event);
    }
    else
    {
        if (action == CURL_POLL_IN)
        {
            pollfd.events |= POLLIN;
            event.events |= EPOLLIN;
        }
        else if (action == CURL_POLL_OUT)
        {
            pollfd.events |= POLLOUT;
            event.events |= EPOLLOUT;
        }
        else if (action == CURL_POLL_INOUT)
        {
            pollfd.events |= (POLLOUT | POLLIN);
            event.events |= (EPOLLOUT | EPOLLOUT);
        }
        else
        {
            printf("Error: Unknown action\n");
            rc = -1;
            goto err_out;
        }

        printf(">>> %s: adding fd=%d action=%d\n", __func__, fd, action);
        if (event.events != 0)
        {
            rc = epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event);

            if (rc == -1)
            {
                rc = epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &event);
                printf("EPOLL_CTL_MOD\n");
            }
            else
            {
                printf("EPOLL_CTL_ADD\n");
            }
        }
    }

err_out:
    return rc;
}


int timerCallback(CURLM* multi, long timeout_ms, void* u)
{
    printf(">>> %s: timeout: %ld ms\n", __func__, timeout_ms);
    timeout = timeout_ms;
    return 0;
}

int main(int argc, char **argv)
{
    int rc;
    CURL *curl_handle;
    CURLcode res;
    struct stream_state ss;
    int epfd;
    struct epoll_event ev;
    struct epoll_event events[10];

    printf("Streaming example... %li\n", sizeof(ss));
    bpak_pkg_register_all_algs();

    pollfd.fd = -1;

    epollFd = epoll_create(1);

    if (epollFd == -1)
        error("epoll_create");

    memset(&ss, 0, sizeof(ss));

    ss.chunk_buffer_size = sizeof(ss.chunk_buffer);

    rc = bpak_io_fifo_init(&ss.fifo, 1024*128);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not setup fifo\n");
        return rc;
    }

    printf("Fifo initialized\n");

    /* Initialize a libcurl handle. */

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL,
                   "http://localhost:8090/vB_transport.bpak");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, stream_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &ss);

    ss.multi = curl_multi_init();
    curl_multi_setopt(ss.multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
    curl_multi_setopt(ss.multi, CURLMOPT_SOCKETDATA, &ss);
    curl_multi_setopt(ss.multi, CURLMOPT_TIMERFUNCTION, timerCallback);

    curl_multi_add_handle(ss.multi, curl_handle);

    int running_handles = 1;

    while (running_handles > 0)
    {
        printf(">>> calling epoll_wait\n");
        struct epoll_event event;
        int res = epoll_wait(epollFd, &event, 1, timeout);

        if (res == -1)
        {
            perror("epoll_wait");
        }
        else if (res == 0)
        {
            curl_multi_socket_action(ss.multi, CURL_SOCKET_TIMEOUT, 0,
                                     &running_handles);
        }
        else
        {
            curl_multi_socket_action(ss.multi, event.data.fd, 0,
                                     &running_handles);
        }
    }

    printf("Finishing...\n");
    while ((ss.state != STATE_DONE) &&
           (ss.state != STATE_FAILED))
    {
        process_update(&ss);
    }

    curl_multi_cleanup(ss.multi);
    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
    close(epfd);
}
