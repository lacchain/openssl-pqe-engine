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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/mman.h>

#include "my_utilslib.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_shmem.h"

// Some ideas from...
// https://opensource.com/article/19/4/interprocess-communication-linux-storage
// Compilation: gcc -o memwriter memwriter.c -lrt -lpthread

// Types
typedef struct tagSHMEMHEADER
{
    uint16_t signature;
    uint16_t version;
    uint32_t tankSize;
    int32_t  waterLevel;
} tSHMEMHEADER;

typedef enum eSHMEM_ACTIVITY
{
    SHMEM_CREATE = 0,
    SHMEM_WRITE,
    SHMEM_GETINFO,
    SHMEM_RETRIEVE
} tSHMEM_ACTIVITY;
static const char *ACTIVITY_NAMES[4] = {"CREATE","WRITE","GETINFO","SHMEM_RETRIEVE"};

// Local Vars
static const unsigned int    __shMemAccessPermissions  = 0666; // 0644;
static char *                __shMemBackingFilename    = "shmem_ibrand01"; // e.g. /dev/shm/shmem_ibrand01
static unsigned long         __shMemSizeInBytes        = sizeof(tSHMEMHEADER) + (100*1024);
static char *                __shMemSemaphoreName      = "sem_ibrand01";

static const int localShMemTracing = false;

// Forward declarations
static bool __ShMem_CheckIntegrity(const char *memptr);
static void __ShMem_PrintStats(const char *memptr, tSHMEM_ACTIVITY currentActivity);
static void shMemCallBackFn_Create(char * memptr, void *userptr);
static void shMemCallBackFn_Write(char * memptr, void *userptr);
static void shMemCallBackFn_GetInfo(char * memptr, void *userptr);
static void shMemCallBackFn_Retrieve(char * memptr, void *userptr);


////////////////////////////////////////////////////////////////////////////
// Local functions
////////////////////////////////////////////////////////////////////////////
static bool __ShMem_DoActivity(tSHMEM_ACTIVITY whichActivity, void *pUserData)
{
    int fd;
    char *szAction;
    int shm_oflags;
    int sem_open_oflags;
    int ReadOnly;
    enum {BEFORE_CALLBACK=0, AFTER_CALLBACK=1, BEFORE_AND_AFTER_CALLBACK=2} checkIntegrity;
    void (*shMemCallBackFn)(char *memptr, void *userptr);
    int timeToSleep;

    switch (whichActivity)
    {
        case SHMEM_CREATE:
            if (localShMemTracing) app_tracef("DEBUG: SHMEM_CREATE");
            szAction = "CREATE";
            shm_oflags = O_RDWR | O_CREAT;
            //sem_open_oflags = O_CREAT | O_EXCL;  // Create the semaphore. Return error if it already exists.
            sem_open_oflags = O_CREAT;  // Create the semaphore.
            ReadOnly = false;
            checkIntegrity = AFTER_CALLBACK;
            shMemCallBackFn = shMemCallBackFn_Create;
            timeToSleep = 0;
            ShMem_DestroyDataStore();
            break;

        case SHMEM_WRITE:
            if (localShMemTracing) app_tracef("DEBUG: SHMEM_WRITE");
            szAction = "OPEN";
            shm_oflags = O_RDWR;
            sem_open_oflags = O_RDWR;  // Return error if the semaphore doesn't already exist
            ReadOnly = false;
            checkIntegrity = BEFORE_AND_AFTER_CALLBACK;
            shMemCallBackFn = shMemCallBackFn_Write;
            timeToSleep = 0;
            break;

        case SHMEM_RETRIEVE:
            if (localShMemTracing) app_tracef("DEBUG: SHMEM_RETRIEVE");
            szAction = "RETRIEVE";
            shm_oflags = O_RDWR;
            sem_open_oflags = O_RDWR;  // Return error if the semaphore doesn't already exist
            ReadOnly = false;
            checkIntegrity = BEFORE_AND_AFTER_CALLBACK;
            shMemCallBackFn = shMemCallBackFn_Retrieve;
            timeToSleep = 0;
            break;

        case SHMEM_GETINFO:
        default:
            if (localShMemTracing) app_tracef("DEBUG: SHMEM_GETINFO");
            szAction = "GETINFO";
            shm_oflags = O_RDWR;      // Read only. The file must already exist.
            sem_open_oflags = O_RDWR;  // Return error if the semaphore doesn't already exist
            ReadOnly = true;
            checkIntegrity = BEFORE_AND_AFTER_CALLBACK;
            shMemCallBackFn = shMemCallBackFn_GetInfo;
            timeToSleep = 0;
            break;
    }

    //if (localShMemTracing) app_tracef("DEBUG: ShMem Open sharedMemory(/dev/shm/%s)", __shMemBackingFilename);
    char tempstr[_MAX_PATH];
    strcpy(tempstr, "/");
    strcat(tempstr, __shMemBackingFilename);
    fd = shm_open(tempstr, shm_oflags, __shMemAccessPermissions);
    if (fd < 0)
    {
        app_tracef("ERROR: Unable to open shared memory segment for %s. errno=%d", szAction, errno);
        return false;
    }

    switch (whichActivity)
    {
        case SHMEM_CREATE:
        //case SHMEM_WRITE:
            //if (localShMemTracing) app_tracef("DEBUG: ShMem Create/Write Calling Truncate(%d)", __shMemSizeInBytes);
            // ftruncate() is not a part of the c99 standard, so either use the gnu99 standard or explicitly prototype the function:
            //   * use flags: gcc -Wall -c program.c -std=gnu99 (See makefile)
            //   * prototype: extern int ftruncate(int fd, off_t length);
            if (ftruncate(fd, __shMemSizeInBytes) != 0)
            {
                app_tracef("ERROR: Unable to set size of shared memory segment. errno=%d", errno);
                return false;
            }
            break;
        case SHMEM_WRITE:
        case SHMEM_GETINFO:
        case SHMEM_RETRIEVE:
        default:
            break;
    }

    // Get a pointer to memory
    char * memptr = mmap(NULL,                    // Let the system pick where to put segment
                         __shMemSizeInBytes,      // Number of bytes
                         PROT_READ | PROT_WRITE,  // Access protections
                         MAP_SHARED,              // Mapping visible to other processes
                         fd,                      // File descriptor
                         0);                      // Offset: start at 1st byte
    if (memptr == (char *)-1)
    {
        app_tracef("ERROR: Failed to access Shared memory segment");
        // Cleanup
        close(fd);
        return false;
    }

    __ShMem_PrintStats(memptr, whichActivity);

    //if (localShMemTracing) app_tracef("DEBUG: Calling sem_open");
    // Before writing to it, we need exclusive access the the shared memory
    // Create a semaphore for mutual exclusion -  to lock the Shared memory
    sem_t* semptr = sem_open( __shMemSemaphoreName,
                              sem_open_oflags,
                              __shMemAccessPermissions,
                              0);                // Initial value
    if (semptr == SEM_FAILED)
    {
        if (errno == EEXIST)
        {
            app_tracef("ERROR: Semaphore already exists");
        }
        else if (errno == ENOENT )
        {
            app_tracef("ERROR: Semaphore does not exist");
        }
        else
        {
            app_tracef("ERROR: Semaphore creation failed. errno=%d", errno);
        }
        // Cleanup
        munmap(memptr, __shMemSizeInBytes); // Unmap the storage
        close(fd);
        return false;
    }

    if (ReadOnly)
    {
        // The reader goes into a wait state until the writer increments the semaphore, whose initial value is 0:

        // Use semaphore as a mutex (lock) by waiting for writer to increment it
        //if (localShMemTracing) app_tracef("DEBUG: Calling sem_wait");
        if (!sem_wait(semptr))  // Wait until semaphore != 0
        {
            // Semaphore has been incremented

            if (checkIntegrity == BEFORE_CALLBACK || checkIntegrity == BEFORE_AND_AFTER_CALLBACK)
            {
                // Check Integrity of dataStore (Id, tankSize vs waterLevel etc)
                if (!__ShMem_CheckIntegrity(memptr))
                {
                    app_tracef("ERROR: Integrity check of shared memory failed");
                    // Cleanup
                    sem_post(semptr);
                    munmap(memptr, __shMemSizeInBytes); // Unmap the storage
                    close(fd);
                    //return false;
                    exit(555);
                }
            }

            // Get what we came for...
            shMemCallBackFn(memptr, pUserData);

            if (checkIntegrity == AFTER_CALLBACK || checkIntegrity == BEFORE_AND_AFTER_CALLBACK)
            {
                // Check Integrity of dataStore (Id, tankSize vs waterLevel etc)
                if (!__ShMem_CheckIntegrity(memptr))
                {
                    app_tracef("ERROR: Integrity check of shared memory failed");
                    // Cleanup
                    sem_post(semptr);
                    munmap(memptr, __shMemSizeInBytes); // Unmap the storage
                    close(fd);
                    //return false;
                    exit(556);
                }
            }

            // Release semaphore
            //if (localShMemTracing) app_tracef("DEBUG: Calling sem_post");
            sem_post(semptr);
        }
    }
    else
    {
        // sem_open() was successful

        if (checkIntegrity == BEFORE_CALLBACK || checkIntegrity == BEFORE_AND_AFTER_CALLBACK)
        {
            // Check Integrity of dataStore (Id, tankSize vs waterLevel etc)
            if (!__ShMem_CheckIntegrity(memptr))
            {
                app_tracef("ERROR: Integrity check of shared memory failed");
                // Cleanup
                sem_post(semptr);
                munmap(memptr, __shMemSizeInBytes); // Unmap the storage
                close(fd);
                //return false;
                exit(557);
            }
        }

        // Do what we came to do...
        if (localShMemTracing) app_tracef("DEBUG: Calling shMemCallBackFn(memptr=%p, pUserData=%p)", memptr, pUserData);
        shMemCallBackFn(memptr, pUserData);
        if (localShMemTracing) app_tracef("DEBUG: Back from shMemCallBackFn(memptr=%p, pUserData=%p)", memptr, pUserData);

        if (checkIntegrity == AFTER_CALLBACK || checkIntegrity == BEFORE_AND_AFTER_CALLBACK)
        {
            // Check Integrity of dataStore (Id, tankSize vs waterLevel etc)
            if (!__ShMem_CheckIntegrity(memptr))
            {
                app_tracef("ERROR: Integrity check of shared memory failed");
                // Cleanup
                sem_post(semptr);
                munmap(memptr, __shMemSizeInBytes); // Unmap the storage
                close(fd);
                //return false;
                exit(558);
            }
        }

        // After writing, we increment the semaphore value to 1 with a call to sem_post().
        // This releases the mutex lock and enables the others to read.
        // For good measure, we will us munmap() to unmap the shared memory from our address space:
        // thus barring further access to the shared memory.

        // Increment the semaphore so that others can have access to the shared memory
        //if (localShMemTracing) app_tracef("DEBUG: Checking sem_post");
        if (sem_post(semptr) < 0)
        {
            app_tracef("ERROR: sem_post failed. errno=%d", errno);
            // Cleanup
            munmap(memptr, __shMemSizeInBytes); // Unmap the storage
            close(fd);
            return false;
        }
        //if (localShMemTracing) app_tracef("DEBUG: Checking sem_post");
    }

    if (timeToSleep > 0)
    {
        // Give and readers a chance
        sleep(timeToSleep);
    }

    // Cleanup
    munmap(memptr, __shMemSizeInBytes); // Unmap the storage
    close(fd);

    //sem_close(semptr);
    // {
    //     char tempstr[_MAX_PATH];
    //     strcpy(tempstr, "/");
    //     strcat(tempstr, __shMemBackingFilename);
    //     shm_unlink(tempstr); // Unlink from the backing file
    // }

    return true;
}

static bool __ShMem_CheckIntegrity(const char *memptr)
{
        const tSHMEMHEADER *pShMemHeader = (tSHMEMHEADER *)memptr;

        uint16_t expectedIdSignature = MAKEWORD(0x4A,0x47);
        uint16_t expectedIdVersion   = MAKEWORD(0x01,0x00);
        uint32_t expectedTankSize    = (__shMemSizeInBytes - sizeof(tSHMEMHEADER));

        if (pShMemHeader->signature != expectedIdSignature)
        {
            app_tracef("ERROR: ShMem Integrity check failed - Invalid Signature [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]", pShMemHeader->signature, pShMemHeader->version, pShMemHeader->tankSize, pShMemHeader->waterLevel);
            return false;
        }
        if (pShMemHeader->version != expectedIdVersion)
        {
            app_tracef("ERROR: ShMem Integrity check failed - Unexpected Version [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]", pShMemHeader->signature, pShMemHeader->version, pShMemHeader->tankSize, pShMemHeader->waterLevel);
            return false;
        }
        if (pShMemHeader->tankSize != expectedTankSize)
        {
            app_tracef("ERROR: ShMem Integrity check failed - Unexpected Size [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]", pShMemHeader->signature, pShMemHeader->version, pShMemHeader->tankSize, pShMemHeader->waterLevel);
            return false;
        }
        if (pShMemHeader->waterLevel < 0)
        {
            app_tracef("ERROR: ShMem Integrity check failed - Invalid Waterlevel [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]", pShMemHeader->signature, pShMemHeader->version, pShMemHeader->tankSize, pShMemHeader->waterLevel);
            return false;
        }
        if (pShMemHeader->waterLevel >= (int32_t)pShMemHeader->tankSize)
        {
            app_tracef("ERROR: ShMem Integrity check failed - Waterlevel overflow [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]", pShMemHeader->signature, pShMemHeader->version, pShMemHeader->tankSize, pShMemHeader->waterLevel);
            return false;
        }
        return true;
}

static void __ShMem_PrintStats(const char *memptr, tSHMEM_ACTIVITY currentActivity)
{
    const tSHMEMHEADER *pShMemHeader = (tSHMEMHEADER *)memptr;

    if (localShMemTracing)
    {
        // app_tracef("DEBUG: ShMem Stats %s [Ptr=%p, File=/dev/shm/%s, "
        //            "Sem=%s, Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]",
        //            ACTIVITY_NAMES[currentActivity], memptr, __shMemBackingFilename,
        //            __shMemSemaphoreName, pShMemHeader->signature,
        //            pShMemHeader->version,  pShMemHeader->tankSize, pShMemHeader->waterLevel);
        if (localShMemTracing) app_tracef("DEBUG: ShMem Stats %s [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]",
                   ACTIVITY_NAMES[currentActivity],
                   pShMemHeader->signature, pShMemHeader->version,
                   pShMemHeader->tankSize, pShMemHeader->waterLevel);
    }
}

////////////////////////////////////////////////////////////////////////////
// Public functions and Callbacks
////////////////////////////////////////////////////////////////////////////

void ShMem_SetBackingFilename(char *szBackingFilename)
{
    // default = "shmem_ibrand01"; // e.g. /dev/shm/shmem_ibrand01
    if (szBackingFilename && strlen(szBackingFilename))
    {
        //app_tracef("INFO: ShMem_SetBackingFilename from [%s] to [%s]", __shMemBackingFilename, szBackingFilename);
        strcpy(__shMemBackingFilename, szBackingFilename);
    }
}

void ShMem_SetStorageSize(size_t sizeOfDataStore)
{
    // default = (100*1024)
    if (sizeOfDataStore)
    {
        //app_tracef("INFO: ShMem_SetStorageSize from [%u] to [%u]", __shMemSizeInBytes - sizeof(tSHMEMHEADER), sizeOfDataStore);
        __shMemSizeInBytes = sizeof(tSHMEMHEADER) + sizeOfDataStore;
    }
}

void ShMem_SetSemaphoreName(char *szSemaphoreName)
{
    // default = "sem_ibrand01"
    if (szSemaphoreName && strlen(szSemaphoreName))
    {
        //app_tracef("INFO: ShMem_SetSemaphoreName from [%s] to [%s]", __shMemSemaphoreName, szSemaphoreName);
        strcpy(__shMemSemaphoreName, szSemaphoreName);
    }
}

static void shMemCallBackFn_Create(char * memptr, void *userptr)
{
        tSHMEMHEADER *pShMemHeader = (tSHMEMHEADER *)memptr;
        char *pShMemData = memptr + sizeof(tSHMEMHEADER);

        UNUSED_PARAM(userptr);

        //if (localShMemTracing) app_tracef("DEBUG: shMemCallBackFn_Create");

        memset(pShMemData, 0, __shMemSizeInBytes);
        pShMemHeader->signature  = MAKEWORD(0x4A,0x47);
        pShMemHeader->version    = MAKEWORD(0x01,0x00);
        pShMemHeader->tankSize   = __shMemSizeInBytes - sizeof(tSHMEMHEADER);
        pShMemHeader->waterLevel = 0;
        //if (localShMemTracing) app_tracef("DEBUG: shMemCallBackFn_Create [Sig=0x%4.4X, Ver=0x%4.4X, Siz=%lu, Lev=%ld]", pShMemHeader->signature, pShMemHeader->version, pShMemHeader->tankSize, pShMemHeader->waterLevel);
}

bool ShMem_CreateDataStore(void)
{
    return __ShMem_DoActivity(SHMEM_CREATE, NULL);
}

static void shMemCallBackFn_Write(char * memptr, void *userptr)
{
    tSHMEMHEADER *pShMemHeader = (tSHMEMHEADER *)memptr;
    char *pShMemData = memptr + sizeof(tSHMEMHEADER);
    unsigned long availableStorage;
    unsigned long bytesToWrite;

    //if (localShMemTracing) app_tracef("DEBUG: shMemCallBackFn_Write");
    tLSTRING *pDataToStore = (tLSTRING *)userptr;
    if (!pDataToStore || !pShMemHeader)
    {
        app_tracef("ERROR: shMemCallBackFn_Write invalid ptr (%p, %p)", pDataToStore, pShMemHeader);
        return;
    }

    availableStorage = pShMemHeader->tankSize - pShMemHeader->waterLevel;
    bytesToWrite = my_minimum(pDataToStore->cbData, availableStorage);
    memcpy(pShMemData + pShMemHeader->waterLevel, pDataToStore->pData, bytesToWrite);
    pShMemHeader->waterLevel += bytesToWrite;
}

bool ShMem_AppendToDataStore(char *pData, size_t cbData)
{
    tLSTRING dataToStore;
    dataToStore.pData = pData;
    dataToStore.cbData = cbData;

    return __ShMem_DoActivity(SHMEM_WRITE, (void *)(&dataToStore));
}

static void shMemCallBackFn_GetInfo(char * memptr, void *userptr)
{
    const tSHMEMHEADER *pShMemHeader = (tSHMEMHEADER *)memptr;
    tSHMEMHEADER *pShCopyOfMemHeader = (tSHMEMHEADER *)userptr;

    if (!pShCopyOfMemHeader || !pShMemHeader)
    {
        app_tracef("ERROR: shMemCallBackFn_GetInfo invalid ptr (%p, %p)", pShMemHeader, pShCopyOfMemHeader);
        return;
    }

    if (localShMemTracing)
    {
        app_tracef("DEBUG: pShMemHeader[%p,%lu]", pShMemHeader, sizeof(tSHMEMHEADER));
        app_trace_hex("ShMemHeader", (const char *)pShMemHeader, sizeof(tSHMEMHEADER));
    }

    memcpy(pShCopyOfMemHeader, pShMemHeader, sizeof(tSHMEMHEADER));
}

bool ShMem_GetInfo(tSHMEMHEADER *pShCopyOfMemHeader)
{
    return __ShMem_DoActivity(SHMEM_GETINFO, (void *)pShCopyOfMemHeader);
}

long ShMem_GetCurrentWaterLevel(void)
{
    tSHMEMHEADER shMemCopyOfHeader;
    long currentWaterLevel = -1;

    memset(&shMemCopyOfHeader, 0, sizeof(tSHMEMHEADER));
    if (ShMem_GetInfo(&shMemCopyOfHeader))
    {
        currentWaterLevel = shMemCopyOfHeader.waterLevel;
    }
    return currentWaterLevel;
}

long ShMem_GetTankSize(void)
{
    tSHMEMHEADER shMemCopyOfHeader;
    long tankSize = -1;

    memset(&shMemCopyOfHeader, 0, sizeof(tSHMEMHEADER));
    if (ShMem_GetInfo(&shMemCopyOfHeader))
    {
        tankSize = shMemCopyOfHeader.tankSize;
    }
    return tankSize;
}

long ShMem_GetAvailableStorage(void)
{
    tSHMEMHEADER shMemCopyOfHeader;
    long availableStorage = -1;

    memset(&shMemCopyOfHeader, 0, sizeof(tSHMEMHEADER));
    if (ShMem_GetInfo(&shMemCopyOfHeader))
    {
        availableStorage = shMemCopyOfHeader.tankSize - shMemCopyOfHeader.waterLevel;
    }

    return availableStorage;
}

static void shMemCallBackFn_Retrieve(char * memptr, void *userptr)
{
    tSHMEMHEADER *pShMemHeader = (tSHMEMHEADER *)memptr;
    char *pShMemData = memptr + sizeof(tSHMEMHEADER);
    unsigned long availableStorage;
    unsigned long bytesToRead;

    //if (localShMemTracing) app_tracef("DEBUG: shMemCallBackFn_Retrieve");
    tLSTRING *pRetrievedData = (tLSTRING *)userptr;
    if (!pRetrievedData || !pShMemHeader)
    {
        app_tracef("ERROR: shMemCallBackFn_Retrieve invalid ptr (%p, %p)", pRetrievedData, pShMemHeader);
        return;
    }

    availableStorage = pShMemHeader->tankSize - pShMemHeader->waterLevel;
    bytesToRead = my_minimum(pRetrievedData->cbData, availableStorage);

    // Get a copy of the data from the dataStore.
    // TODO: Change to FIFO. Currently LIFO - not ideal, but ok for PoC
    memcpy(pRetrievedData->pData, pShMemData + pShMemHeader->waterLevel - bytesToRead, bytesToRead);
    // Destroy the original
    memset(pShMemData + pShMemHeader->waterLevel - bytesToRead, 0xFF, bytesToRead);
    // Adjust the waterlevel (and write pointer)
    pShMemHeader->waterLevel -= bytesToRead;
    // Comminicate back to the caller the number of bytes actually retrieved.
    pRetrievedData->cbData = bytesToRead;
}

int32_t ShMem_RetrieveFromDataStore(char *pData, size_t cbData)
{
    tLSTRING retrievedData;
    retrievedData.pData = pData;
    retrievedData.cbData = cbData;

    if (localShMemTracing) app_tracef("DEBUG: ShMem_RetrieveFromDataStore Requested: %u", cbData);
    bool success = __ShMem_DoActivity(SHMEM_RETRIEVE, (void *)(&retrievedData));
    if (!success)
    {
        return -1;
    }
    // Return bytesRead (and removed)
    if (localShMemTracing) app_tracef("DEBUG: ShMem_RetrieveFromDataStore Returning: %u", retrievedData.cbData);
    return retrievedData.cbData;
}

bool ShMem_DestroyDataStore(void)
{
    //sem_close(semptr);

    // {
    //     char tempstr[_MAX_PATH];
    //     strcpy(tempstr, "/");
    //     strcat(tempstr, __shMemBackingFilename);
    //     shm_unlink(tempstr); // Unlink from the backing file
    // }
    return true;
}
