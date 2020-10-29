
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

#include "my_utilslib.h"
#include "ibrand_service_shmem.h"
#include "libibrand_config.h"
#include "libibrand.h"
#include "libibrand_get_new_entropy.h"

static const int localDebugTracing = false;

static bool GetNewEntropyFromFile(struct ibrand_context *context, char *szIBDatafilename, char *szStorageLockfilePath, uint8_t *inBuf, size_t inBufLen);
static bool GetNewEntropyFromSharedMemory(struct ibrand_context *context, uint8_t *inBuf, size_t inBufLen);



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
        rc = GetNewEntropyFromSharedMemory(context, inBuf, inBufLen);
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
    //fprintf(stderr, ".");
    return success;
}

static bool GetNewEntropyFromSharedMemory(struct ibrand_context *context, uint8_t *inBuf, size_t inBufLen)
{
    int32_t bytesToRead;
    int32_t bytesRead;
    int32_t waterLevel;

    bytesToRead = inBufLen;

    if (localDebugTracing)
        //if (localDebugTracing) app_tracef("DEBUG: GetNewEntropyFromSharedMemory [Attempt %d] -------------- <<<", numFailedReads);

    // Ensure that there is enough data
    waterLevel = ShMem_GetCurrentWaterLevel();
    if (waterLevel < bytesToRead)
    {
        sprintf(context->tempMessageBuffer200, "ERROR: Insufficient data in IB DataStore (requested=%lu, available=%d)", (unsigned long)bytesToRead, waterLevel);
        context->message = context->tempMessageBuffer200;
        context->errorCode = 13705;
        return false;
    }

    // Read the data and remove the data we have just read.
    bytesRead = ShMem_RetrieveFromDataStore((char *)inBuf, bytesToRead);
    if (bytesRead < 0)
    {
        context->message = "ERROR: IB DataStore read error - see log above for more details";
        context->errorCode = 13706;
        return false;
    }
    if (bytesRead != bytesToRead)
    {
        sprintf(context->tempMessageBuffer200, "ERROR: Failed to read enough data from IB DataStore (requested=%lu, delivered=%lu)", (unsigned long)bytesToRead, (unsigned long)bytesRead);
        context->message = context->tempMessageBuffer200;
        context->errorCode = 13707;
        return false;
    }
    return true;
}
