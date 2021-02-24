///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
// Original: JGilmore (2020/06/23 15:26:31)
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

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

#include "../ibrand_common/my_utilslib.h"
#include "ibrand_get_new_entropy.h"
#include "ibrand_config.h"

tIB_INSTANCEDATA *pIBRand = NULL;
static const int localDebugTracing = false;

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
bool IBRand_init(struct ibrand_context *context)
{
    context->message = "";
    context->errorCode = 0;

    pIBRand = cfgInitConfig();
    if (!pIBRand)
    {
        app_tracef("FATAL: Failed to initialise config. Aborting.");
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
void IBRand_deinit(struct ibrand_context *context)
{
    UNUSED_VAR(context);
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
uint32_t IBRand_readData(struct ibrand_context *context, uint8_t *pResult, size_t cbResult)
{
    static int fReadDataIsBusy = 0;
    uint32_t quantitySupplied = 0;

    if (pResult == NULL || cbResult == 0)
    {
        context->message = "IBRand_readData parameter error";
        context->errorCode = 13709;
        return 0;
    }

    if (fReadDataIsBusy > 0)
    {
        context->message = "IBRand_readData is busy";
        context->errorCode = 13708;
        return 0;
    }

    if (localDebugTracing) app_tracef("DEBUG: IBRand_readData - requesting %lu bytes", (unsigned long)cbResult);

    fReadDataIsBusy++;
    do
    {
        context->errorCode = 0;
        if (!GetNewEntropy(context, pIBRand, pResult, cbResult))
        {
            app_tracef("ERROR: GetNewEntropy failed. errorCode=%d: msg=%s", context->errorCode, context->message?context->message:"<No message supplied>");
            quantitySupplied = 0;
            break;
        }
        quantitySupplied = cbResult;
    } while (false);

    fReadDataIsBusy--;
    return quantitySupplied;
}
