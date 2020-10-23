
#ifndef _INCLUDE_LIBIBRAND_H_
#define _INCLUDE_LIBIBRAND_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <limits.h>
#elif !defined(_WIN32)
#include <linux/limits.h>
#endif
#include <time.h>

#define BUFLEN 512u

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_WIN32)
struct ibrand_context
{
    const char *message;
    char tempMessageBuffer200[200];
    int errorCode;
};

extern bool initIBRand(struct ibrand_context *context);
extern void deinitIBRand(struct ibrand_context *context);
extern uint32_t readData(struct ibrand_context *context, uint8_t *result, size_t result_buffer_size/*, bool raw, uint32_t outputMultiplier*/);

#ifdef __cplusplus
}
#endif

#endif

#endif // _INCLUDE_LIBIBRAND_H_
