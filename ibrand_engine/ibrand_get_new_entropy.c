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

#include "../ibrand_common/my_utils.h"
#include "../ibrand_common/my_filelock.h"
#include "../ibrand_common/my_logging.h" // For app_tracef()
#include "../ibrand_service/ibrand_service_shmem.h" // For ShMem_GetCurrentWaterLevel() & ShMem_RetrieveFromDataStore()

#include "ibrand_main.h"
#include "ibrand_get_new_entropy.h"

static const int localDebugTracing = false;

static bool GetNewEntropyFromFile(struct ibrand_context *context, char *szIBDatafilename, char *szStorageLockfilePath, uint8_t *inBuf, size_t inBufLen);
static bool GetNewEntropyFromSharedMemory(struct ibrand_context *context, uint8_t *inBuf, size_t inBufLen, int delayBetweenAttempts, int numAttempts);



bool GetNewEntropy(struct ibrand_context *context, tIB_INSTANCEDATA *pIBRand, uint8_t *inBuf, size_t inBufLen)
{
    bool rc = false;

    //if (localDebugTracing) app_tracef("DEBUG: GetNewEntropy inBufLen: %u", inBufLen);

    if (strcmp(pIBRand->cfg.szStorageType, "FILE") == 0)
    {
        char filename[_MAX_PATH];
        cfgGetDatafilename(filename, sizeof(filename), pIBRand );
        rc = GetNewEntropyFromFile(context, filename, pIBRand->cfg.szStorageLockfilePath, inBuf, inBufLen);
    }
    if (strcmp(pIBRand->cfg.szStorageType, "SHMEM") == 0)
    {
        int delayBetweenAttempts = 2; // Seconds
        int numAttempts = 20;
        rc = GetNewEntropyFromSharedMemory(context, inBuf, inBufLen, delayBetweenAttempts, numAttempts );
    }
    return rc;
}

static bool GetNewEntropyFromFile(struct ibrand_context *context, char *szIBDatafilename, char *szStorageLockfilePath, uint8_t *inBuf, size_t inBufLen)
{
    FILE * fIBDatafile = NULL;
    char * szLockfilePath = szStorageLockfilePath; // "/tmp";
    size_t bytesToRead;
    bool   success = false;

    bytesToRead = inBufLen;

    my_waitForFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);

    do // Not a real loop - just an exitable code block
    {
        size_t bytesRead;
        size_t filesize;

        // Open the file
        fIBDatafile = fopen(szIBDatafilename,"rb");
        if (fIBDatafile == NULL)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Unable to open IBDatafile (%s)\n", szIBDatafilename );
            context->message = context->tempMessageBuffer200;
            context->errorCode = 13701;
            break;
        }

        // Ensure that there is enough data
        fseek (fIBDatafile, 0, SEEK_END);
        filesize = ftell(fIBDatafile);
        rewind(fIBDatafile);
        if (filesize < bytesToRead)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Insufficient data in IBDatafile (requested=%lu, actual=%lu)\n", (unsigned long)bytesToRead, (unsigned long)filesize);
            context->message = context->tempMessageBuffer200;
            context->errorCode = 13702;
            break;
        }

        // Read the data
        // Not ideal, but for now we will read from the end of the file, and then truncate what we have read.
        // TODO: Change to FIFO. Currently LIFO - not ideal, but ok for PoC
        fseek (fIBDatafile, filesize - bytesToRead, SEEK_SET);
        bytesRead = fread(inBuf, sizeof(char), bytesToRead, fIBDatafile);
        if (bytesRead != bytesToRead)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Failed to read all requested data from IB DataStore (requested=%lu, delivered=%lu)", (unsigned long)bytesToRead, (unsigned long)bytesRead);
            context->message = context->tempMessageBuffer200;
            context->errorCode = 13703;
            break;
        }

        // ...and close the file
        fclose(fIBDatafile);
        fIBDatafile = NULL;

        // Then... remove the data we have just read.
        if (truncate(szIBDatafilename, filesize - bytesToRead) != 0)
        {
            context->message = "ERROR: Unable to remove the data from the file";
            context->errorCode = 13704;
            break;
        }
        success = true;
    } while (false);

    if (fIBDatafile)
    {
        fclose(fIBDatafile);
        fIBDatafile = NULL;
    }
    my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);
    return success;
}

static bool GetNewEntropyFromSharedMemory(struct ibrand_context *context, uint8_t *inBuf, size_t inBufLen, int delayBetweenAttempts, int numAttempts)
{
    bool rc;
    int32_t bytesToRead;
    int32_t bytesRead = 0;
    int32_t waterLevel;
    int numFailedReads = 0;
    int numSuccessfulReads = 0;
    bool doDelay = false;

    bytesToRead = inBufLen;

    if (localDebugTracing) app_tracef("DEBUG: GetNewEntropyFromSharedMemory bytesToRead=%u, delayBetweenAttempts=%d, numAttempts=%d", bytesToRead, delayBetweenAttempts, numAttempts);

    for (numFailedReads = 0; numFailedReads < numAttempts; )
    {
        //if (localDebugTracing) app_tracef("DEBUG: GetNewEntropyFromSharedMemory [Attempt %d] -------------- <<<", numFailedReads);

        // Should we give the ibrand_service a bit more time?
        if (doDelay)
        {
            if (localDebugTracing) app_tracef("INFO: Problem acquiring new entropy. Will retry in %d seconds", delayBetweenAttempts);
            if (delayBetweenAttempts > 0)
            {
                sleep(delayBetweenAttempts);
            }
            if (localDebugTracing) app_tracef("DEBUG: Awake");
            doDelay = false;
        }

        // Ensure that there is enough data
        waterLevel = ShMem_GetCurrentWaterLevel();
        context->recentWaterLevel = waterLevel;

        // If there is _some_ water, then drop through and let the retrieval code send back what it can.
        // if (waterLevel < bytesToRead)
        // Only loop if the tank is bone dry
        if (waterLevel == 0)
        {
            context->errorCode = 13705;
            numFailedReads++;
            doDelay = true;
            continue;
        }

        // All good. Let's go and get it.
        // Read the data and remove the data we have just read.
        bytesRead = ShMem_RetrieveFromDataStore((char *)inBuf, bytesToRead);
        if (bytesRead < 0)
        {
            // A genuine error has occured
            context->errorCode = 13706;
            numFailedReads++;
            doDelay = true;
            continue;
        }
        // We got some data, although maybe not all
        numSuccessfulReads++;
        if (bytesRead != bytesToRead)  // BytesRead = my_minimum(requestedQty, availableStorage);
        {
            bytesToRead -= bytesRead;
            inBuf += bytesRead;
            continue;
        }
        context->errorCode = 0;
        break; // All good
    }

    switch (context->errorCode)
    {
        case 0: // All good
            sprintf(context->tempMessageBuffer200, "INFO: Acquired requested data (requested=%lu, OKreads=%d, NGreads=%d)", (unsigned long)bytesToRead, numSuccessfulReads, numFailedReads);
            context->message = context->tempMessageBuffer200;
            //context->tempMessageBuffer200[0] = 0;
            //context->message = NULL;
            rc = true;
            break;
        case 13705: // Insufficient data in IB DataStore
            sprintf(context->tempMessageBuffer200, "ERROR: Insufficient data in IB DataStore (requested=%lu, available=%d)", (unsigned long)bytesToRead, waterLevel);
            context->message = context->tempMessageBuffer200;
            rc = false;
            break;
        case 13706: // IB DataStore read error
            context->message = "ERROR: IB DataStore read error";
            rc = false;
            break;
        case 13707: // IB DataStore read error
            sprintf(context->tempMessageBuffer200, "ERROR: Failed to read enough data from IB DataStore (requested=%lu, delivered=%lu)", (unsigned long)bytesToRead, (unsigned long)bytesRead);
            context->message = context->tempMessageBuffer200;
            rc = false;
            break;
        default: // Unknown error
            context->message = "ERROR: GetNewEntropy failed. Unknown error";
            rc = false;
            break;
    }
    if (localDebugTracing) app_tracef("DEBUG: GetNewEntropyFromSharedMemory err:%d msg:%s", context->errorCode, context->message);

    return rc;
}
