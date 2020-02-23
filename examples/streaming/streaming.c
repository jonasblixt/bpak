#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/file.h>
#include <bpak/utils.h>
#include <curl/curl.h>

enum states
{
    STATE_LOAD_HEADER,
    STATE_PROCESS_PARTS,
    STATE_DONE,
    STATE_FAILED,
};

struct stream_state
{
    struct bpak_header header;
    struct bpak_part_header *part;
    uint64_t stream_pos;
    enum states state;
};

static size_t stream_cb(void *contents, size_t length, size_t nmemb,
                                  void *userp)
{
    size_t real_size = length * nmemb;
    struct stream_state *ss = (struct stream_state *) userp;
    int rc;

    switch (ss->state)
    {
        case STATE_LOAD_HEADER:
        {
            /* TODO: Assumption: At least 4kByte of data available */
            memcpy(&ss->header, contents, sizeof(ss->header));
            
            rc = bpak_valid_header(&ss->header);

            if (rc != BPAK_OK)
            {
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

            ss->part = ss->header.parts;
            ss->state = STATE_PROCESS_PARTS;
        }
        break;
        case STATE_PROCESS_PARTS:
        {
            printf("Processing part: %x\n", ss->part->id);

            ss->part++;

            if (!ss->part->id)
            {
                printf("Done\n");
                ss->state = STATE_DONE;
            }
        }
        break;
        case STATE_DONE:
        break;
        case STATE_FAILED:
        {
            printf("STATE_FAILED\n");
        }
        default:
        {
            printf("Unknown state %i\n", ss->state);
        }
        break;
    }

    return real_size;
}

int main(int argc, char **argv)
{
    CURL *curl_handle;
    CURLcode res;
    struct stream_state ss;

    printf("Streaming example...\n");

    memset(&ss, 0, sizeof(ss));

    /* Initialize a libcurl handle. */ 
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL,
                   "http://localhost:8080/vB_transport.bpak");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, stream_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &ss);

    /* Perform the request and any follow-up parsing. */ 
    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
}
