#ifndef LINUX_KERNEL_API_6_1_75_H_
#define LINUX_KERNEL_API_6_1_75_H_
#include "../ver_control.h"
#if MY_LINUX_VERSION_CODE == KERNEL_VERSION(6,1,75)

long copy_from_kernel_nofault(void* dst, const void* src, size_t size);

MY_STATIC long x_probe_kernel_read(void* bounce, const char* ptr, size_t sz) {
    // source: drivers/char/mem.c
    return copy_from_kernel_nofault(bounce, ptr, sz);
}

#endif
#endif /* LINUX_KERNEL_API_6_1_75_H_ */

