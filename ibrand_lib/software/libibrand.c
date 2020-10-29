
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
bool isSuperUser(void)
{
    return (geteuid() == 0);
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
uint32_t readData(struct ibrand_context *context, uint8_t *pResult, size_t cbResult)
{
    static int fReadDataIsBusy = 0;
    uint32_t rc;

    if (pResult == NULL || cbResult == 0)
    {
        return 0;
    }

    if (fReadDataIsBusy > 0)
    {
        context->message = "readData is busy";
        context->errorCode = 13708;
        return 0;
    }

    if (localDebugTracing) app_tracef("DEBUG: readData Requested: %lu\n", (unsigned long)cbResult);

    fReadDataIsBusy++;
    {
        // Collect new entropy
        context->errorCode = 0;
        if (!GetNewEntropy(context, pIBRand, pResult, cbResult))
        {
            app_tracef("ERROR: GetNewEntropy failed. errorCode=%d: msg=%s\n", context->errorCode, context->message?context->message:"<No message supplied>");
            rc = 0;
        }
        else
        {
            rc = cbResult;
        }
    }
    fReadDataIsBusy--;
    return rc;
}
