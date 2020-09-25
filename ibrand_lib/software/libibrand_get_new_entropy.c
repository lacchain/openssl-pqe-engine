/* Library for the Infinite Noise Multiplier USB stick */

// Required to include clock_gettime
#define _POSIX_C_SOURCE 200809L

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

//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
#include <ftdi.h>
#include "libibrand_private.h"
#include "KeccakF-1600-interface.h"
//#endif

#include "my_utilslib.h"
#include "ibrand_service_shmem.h"
#include "libibrand_config.h"
#include "libibrand.h"
#include "libibrand_get_new_entropy.h"

static bool GetNewEntropyFromFile(struct ibrand_context *context, char *szIBDatafilename, char *szStorageLockfilePath, uint8_t *inBuf);
static bool GetNewEntropyFromSharedMemory(struct ibrand_context *context, uint8_t *inBuf);

bool GetNewEntropy(struct ibrand_context *context, tIB_INSTANCEDATA *pIBRand, uint8_t *inBuf)
{
    bool rc = false;

    if (strcmp(pIBRand->cfg.szStorageType, "FILE") == 0)
    {
        char filename[_MAX_PATH];
        cfgGetDatafilename(filename, sizeof(filename), pIBRand );
        rc = GetNewEntropyFromFile(context, filename, pIBRand->cfg.szStorageLockfilePath, inBuf);
    }
    if (strcmp(pIBRand->cfg.szStorageType, "SHMEM") == 0)
    {
        rc = GetNewEntropyFromSharedMemory(context, inBuf);
    }
    return rc;
}

static bool GetNewEntropyFromFile(struct ibrand_context *context, char *szIBDatafilename, char *szStorageLockfilePath, uint8_t *inBuf)
{
    FILE * fIBDatafile = NULL;
    char * szLockfilePath = szStorageLockfilePath; // "/tmp";
    size_t filesize;
    size_t bytesToRead;
    size_t bytesRead;
    bool   success = false;

    bytesToRead = sizeof(inBuf);

    my_waitForFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);

    for(;;) // Not a real loop - just an exitable code block
    {
        // Open the file
        fIBDatafile = fopen(szIBDatafilename,"rb");
        if (fIBDatafile == NULL)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Unable to open IBDatafile (%s)\n", szIBDatafilename );
            context->message = context->tempMessageBuffer200;
            context->errorFlag = true;
            break;
        }

        // Ensure that there is enough data
        fseek (fIBDatafile, 0, SEEK_END);
        filesize = ftell(fIBDatafile);
        rewind(fIBDatafile);
        if (filesize < bytesToRead)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Insufficient data in IBDatafile (requested=%lu, actual=%lu)\n", bytesToRead, filesize);
            context->message = context->tempMessageBuffer200;
            context->errorFlag = true;
            break;
        }

        // Read the data
        // Not ideal, but for now we will read from the end of the file, and then truncate what we have read.
        // TODO: Change to FIFO. Currently LIFO - not ideal, but ok for PoC
        fseek (fIBDatafile, filesize - bytesToRead, SEEK_SET);
        bytesRead = fread(inBuf, sizeof(char), bytesToRead, fIBDatafile);
        if (bytesRead != bytesToRead)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Failed to read all requested data from IB DataStore (requested=%lu, delivered=%lu)", bytesToRead, bytesRead);
            context->message = context->tempMessageBuffer200;
            context->errorFlag = true;
            break;
        }

        // ...and close the file
        fclose(fIBDatafile);
        fIBDatafile = NULL;

        // Then... remove the data we have just read.
        if (truncate(szIBDatafilename, filesize - bytesToRead) != 0)
        {
            context->message = "ERROR: Unable to remove the data from the file";
            context->errorFlag = true;
            break;
        }
        success = true;
        break;
    }

    if (fIBDatafile)
    {
        fclose(fIBDatafile);
        fIBDatafile = NULL;
    }
    my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);
    //printf(".");
    return success;
}

static bool GetNewEntropyFromSharedMemory(struct ibrand_context *context, uint8_t *inBuf)
{
    size_t bytesToRead;
    size_t bytesRead;
    bool   success = false;

    bytesToRead = sizeof(inBuf);

    for(;;) // Not a real loop - just an exitable code block
    {
        // Ensure that there is enough data
        int32_t waterLevel = ShMem_GetCurrentWaterLevel();
        if (waterLevel < (int32_t)bytesToRead)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Insufficient data in IB DataStore (requested=%lu, available=%d)", bytesToRead, waterLevel);
            context->message = context->tempMessageBuffer200;
            context->errorFlag = true;
            break;
        }

        // Read the data and remove the data we have just read.
        bytesRead = ShMem_RetrieveFromDataStore((char *)inBuf, bytesToRead);
        if (bytesRead <= 0)
        {
            context->message = "ERROR: IB DataStore read error - see log above for more details";
            context->errorFlag = true;
            break;
        }
        if (bytesRead != bytesToRead)
        {
            sprintf(context->tempMessageBuffer200, "ERROR: Failed to read enough data from IB DataStore (requested=%lu, delivered=%lu)", bytesToRead, bytesRead);
            context->message = context->tempMessageBuffer200;
            context->errorFlag = true;
            break;
        }
        success = true;
        break;
    }
    return success;
}
