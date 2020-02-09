#include <stdio.h>
#include <stdarg.h>
#include <bpak/bpak.h>

int bpak_printf(int verbosity, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return BPAK_OK;
}

