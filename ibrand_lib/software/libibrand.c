
#define _POSIX_C_SOURCE 200809L  // Required to include clock_gettime

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <syslog.h>

#include "libibrand_globals.h"

#include "libibrand_private.h"

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__FreeBSD__)
#include <fcntl.h>
#endif

#include "my_utilslib.h"
#include "libibrand_get_new_entropy.h"
#include "libibrand_config.h"

tIB_INSTANCEDATA *pIBRand = NULL;

static const int localDebugTracing = false;

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
bool initIBRand(struct ibrand_context *context)
{
    context->message = "";
    context->errorCode = 0;

    pIBRand = cfgInitConfig();
    if (!pIBRand)
    {
        app_tracef("FATAL: Failed to initialise config. Aborting.\n");
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
void deinitIBRand(struct ibrand_context *context)
{
    UNUSED_VAR(context);
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
uint32_t processBytes(uint8_t *pBytes,
                      size_t   cbBytes,
                      uint8_t *pResult,
                      size_t   cbResult)
{
    size_t bytesToCopy = 0;

    if (pResult != NULL)
    {
        bytesToCopy = my_minimum(cbBytes, cbResult);
        if (localDebugTracing) fprintf(stderr, "[ibrand_lib] DEBUG: processBytes: Fill pResult with %lu bytes\n", (unsigned long)bytesToCopy);
        memcpy(pResult, pBytes, bytesToCopy);
    }

    return bytesToCopy;
}

////////////////////////////////////////////////////////////////////////////////
// Return the difference in the times as a double in microseconds.
////////////////////////////////////////////////////////////////////////////////
double diffTime(struct timespec *start, struct timespec *end)
{
    uint32_t seconds = end->tv_sec - start->tv_sec;
    int32_t nanoseconds = end->tv_nsec - start->tv_nsec;
    return seconds * 1.0e6 + nanoseconds / 1000.0;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
bool isSuperUser(void)
{
    return (geteuid() == 0);
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
static uint32_t readData_Protected(struct ibrand_context *context, uint8_t *result, size_t result_buffer_size);

uint32_t readData(struct ibrand_context *context, uint8_t *result, size_t result_buffer_size)
{
    static int fReadDataIsBusy = 0;
    uint32_t rc;

    if (fReadDataIsBusy > 0)
    {
        context->message = "readData is busy";
        context->errorCode = 13708;
        return 0;
    }

    if (localDebugTracing) app_tracef("DEBUG: readData Requested: %lu\n", (unsigned long)cbResult);

    fReadDataIsBusy++;
    rc = readData_Protected(context, result, result_buffer_size);
    fReadDataIsBusy--;
    return rc;
}

static uint32_t readData_Protected(struct ibrand_context *context, uint8_t *result, size_t result_buffer_size)
{
    // Collect new entropy
    uint8_t inBuf[BUFLEN];
    struct timespec start;
    struct timespec end;
    uint32_t elapsedTime_us;

    clock_gettime(CLOCK_REALTIME, &start);

    size_t bytesToGet = sizeof(inBuf);

    context->errorCode = 0;
    if (!GetNewEntropy(context, pIBRand, inBuf, bytesToGet))
    {
            app_tracef("ERROR: GetNewEntropy failed. errorCode=%d: msg=%s\n", context->errorCode, context->message?context->message:"<No message supplied>");
        return 0;
    }

    clock_gettime(CLOCK_REALTIME, &end);

    elapsedTime_us = diffTime(&start, &end);
    if (elapsedTime_us > MAX_MICROSEC_FOR_SAMPLES)
    {
        // The maximum allowed time to perform the I/O operations was exceeded possibly causing reduced entropy.
        context->message = "ERROR: The time to acquire the data was exceeded resulting in possible reduced entropy.";
        context->errorCode = 13709;
        return 0;
    }

    uint32_t ret;
    ret = processBytes( inBuf, // bytes,
                        bytesToGet,
                        result,
                        result_buffer_size );
    return ret;
}
