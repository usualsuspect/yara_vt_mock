#include "utils.h"
#include <stdarg.h>
#include <stdio.h>

//#define DEBUG

void dbg_print(const char *fmt,...)
{
    va_list ptr;
    va_start(ptr,fmt);
#ifdef DEBUG
    vfprintf(stderr,fmt,ptr);
#endif
    va_end(ptr);
}