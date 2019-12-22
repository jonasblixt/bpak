#include <bpak/bpak.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int code;
    memcpy(&code, data, size>4?4:size);
    bpak_error_string(code);
    return 0;
}
