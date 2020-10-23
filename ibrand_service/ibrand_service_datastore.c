///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ibrand_service.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_config.h"
#include "ibrand_service_shmem.h"
#include "ibrand_service_datastore.h"

static const int localDebugTracing = false;

long dataStore_GetCurrentWaterLevel(tIB_INSTANCEDATA *pIBRand)
{
    long currentWaterLevel = -1;

    if (strcmp(pIBRand->cfg.szStorageType,"FILE")==0)
    {
        currentWaterLevel = my_getFilesize(pIBRand->cfg.szStorageFilename);
        //if (localDebugTracing) app_tracef("DEBUG: Filename=\"%s\", currentWaterLevel=%d", pIBRand->szStorageFilename, currentWaterLevel);
    }
    else if (strcmp(pIBRand->cfg.szStorageType,"SHMEM")==0)
    {

        currentWaterLevel = ShMem_GetCurrentWaterLevel();
        //if (localDebugTracing) app_tracef("DEBUG: Filename=\"%s\", currentWaterLevel=%d", pIBRand->szStorageFilename, currentWaterLevel);
    }

    return currentWaterLevel;
}

long dataStore_GetAvailableStorage(tIB_INSTANCEDATA *pIBRand)
{
    long availableStorage = -1;

    if (strcmp(pIBRand->cfg.szStorageType,"FILE")==0)
    {
        availableStorage = pIBRand->cfg.storageHighWaterMark - my_getFilesize(pIBRand->cfg.szStorageFilename);
        //if (localDebugTracing) app_tracef("DEBUG: Filename=\"%s\", currentWaterLevel=%d", pIBRand->szStorageFilename, availableStorage);
    }
    else if (strcmp(pIBRand->cfg.szStorageType,"SHMEM")==0)
    {

        availableStorage = ShMem_GetAvailableStorage();
        //if (localDebugTracing) app_tracef("DEBUG: Filename=\"%s\", currentWaterLevel=%d", pIBRand->szStorageFilename, availableStorage);
    }

    return availableStorage;
}

bool dataStore_Initialise(tIB_INSTANCEDATA *pIBRand)
{
    if (strcmp(pIBRand->cfg.szStorageType,"FILE")==0)
    {
        // Ensure that we don't still have a lock file from a previous run
        my_releaseFileLock(pIBRand->cfg.szStorageLockfilePath, pIBRand->cfg.szStorageFilename, FILELOCK_LOGLEVEL);
    }
    else if (strcmp(pIBRand->cfg.szStorageType,"SHMEM")==0)
    {
        //ShMem_SetBackingFilename (pIBRand->cfg.shMemBackingFilename); // char[128] // "shmem_ibrand01" e.g. /dev/shm/shmem_ibrand01
        //ShMem_SetStorageSize     (pIBRand->cfg.shMemStorageSize    );  // long      // (100*1024)
        //ShMem_SetSemaphoreName   (pIBRand->cfg.shMemSemaphoreName  ); // char[16]  // "sem_ibrand01"

        if (localDebugTracing) app_tracef("DEBUG: Calling ShMem_CreateDataStore");
        if (!ShMem_CreateDataStore())
        {
           return false;
        }
    }
    return true;
}

static unsigned int __dataStore_AppendToFile(char *pData,
                                    size_t cbData,
                                    char *szStorageFilename,
                                    char *szStorageLockfilePath,
                                    char *szStorageDataFormat)
{
    //if (localDebugTracing) fprintf(stdout, "[ibrand-service] %u:%s\n", pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    FILE *f;
    unsigned int bytesWritten1 = 0;
    unsigned int bytesWritten2 = 0;

    my_waitForFileLock(szStorageLockfilePath, szStorageFilename, FILELOCK_LOGLEVEL);
    f = fopen(szStorageFilename,"ab");
    if (!f)
    {
        app_tracef("WARNING: Unable to open storage file. Discarding %u bytes.", cbData);
        my_releaseFileLock(szStorageLockfilePath, szStorageFilename, FILELOCK_LOGLEVEL);
        // ...and sleep a little in the hope that it will recover
        sleep(1);
        return 0;
    }
    bytesWritten1 = fwrite(pData, 1, cbData, f);
    if (bytesWritten1 != cbData)
    {
        app_tracef("WARNING: Failed to write all bytes (%d/%d)", bytesWritten1, cbData);
    }
    // Delimit each Base64 block with a LF
    if (strcmp(szStorageDataFormat,"BASE64")==0)
    {
        bytesWritten2 = fwrite("\n", 1, 1, f);
        if (bytesWritten2 != 1)
        {
            app_tracef("WARNING: Unable to write LF");
        }
    }
    fclose(f);
    my_releaseFileLock(szStorageLockfilePath, szStorageFilename, FILELOCK_LOGLEVEL);
    return bytesWritten1 + bytesWritten2;
}

bool dataStore_Append(tIB_INSTANCEDATA *pIBRand)
{
    unsigned int bytesWritten = 0;
    if (strcmp(pIBRand->cfg.szStorageType,"FILE")==0)
    {
        bytesWritten = __dataStore_AppendToFile(pIBRand->ResultantData.pData,
                                                pIBRand->ResultantData.cbData,
                                                pIBRand->cfg.szStorageFilename,
                                                pIBRand->cfg.szStorageLockfilePath,
                                                pIBRand->cfg.szStorageDataFormat);
    }
    else if (strcmp(pIBRand->cfg.szStorageType,"SHMEM")==0)
    {
        bytesWritten = ShMem_AppendToDataStore(pIBRand->ResultantData.pData,
                                               pIBRand->ResultantData.cbData);
    }
    else
    {
        app_tracef("WARNING: Unsupported storage type \"%s\". Discarding %u bytes.", pIBRand->cfg.szStorageType, pIBRand->ResultantData.cbData);
        return false;
    }
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s - %u bytes stored to %s", pIBRand->cfg.useSecureRng?"SRNG":"RNG",
                                                       bytesWritten,
                                                       pIBRand->cfg.szStorageType);
    }
    return true;
}
