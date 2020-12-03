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

#ifndef _INCLUDE_LIBIBRAND_CONFIG_H_
#define _INCLUDE_LIBIBRAND_CONFIG_H_

#include <stdlib.h>
#include <stdint.h>

#include "../../ibrand_common/my_utils.h"

#define DBGBIT_STATUS   0
#define DBGBIT_CONFIG   1
#define DBGBIT_PROGRESS 2
#define DBGBIT_AUTH     3
#define DBGBIT_DATA     4
#define DBGBIT_CURL     5
#define DBGBIT_SPARE5   6
#define DBGBIT_SPARE6   7


typedef struct tagIB_CONFIGDATA
{
    // Configuration
    unsigned char  fVerbose;                        // bitmapped field
    // Storage
    char          szStorageType[16];                // "FILE", "SHMEM"
    char          szStorageDataFormat[16];          // RAW, BASE64, HEX
    char          szStorageFilename[_MAX_PATH];     // "/var/lib/ibrand/ibrand_data.bin"
    char          szStorageLockfilePath[_MAX_PATH]; // "/tmp"
    long          storageHighWaterMark;             // 1038336 // 1MB
    long          storageLowWaterMark;              // 102400  // 100KB
    char          shMemBackingFilename[_MAX_PATH];  // "shmem_ibrand01" // e.g. /dev/shm/shmem_ibrand01
    char          shMemSemaphoreName[16];           // "sem_ibrand01"
    long          shMemStorageSize;                 // (100*1024)
    long          shMemLowWaterMark;                // 102400  // 100KB
} tIB_CONFIGDATA;

typedef struct tagIB_INSTANCEDATA
{
    tIB_CONFIGDATA cfg;

    // State
    char          szConfigFilename[_MAX_PATH];      //  "/usr/local/ssl/ibrand.cnf"
} tIB_INSTANCEDATA;

extern tIB_INSTANCEDATA *cfgInitConfig      (void);
extern int               cfgReadConfig      (char *szConfigFilename, tIB_INSTANCEDATA *pIBRand);
extern char *            cfgGetValue        (char *szEnvVariableWithFilename, char *szKey);
extern void              cfgGetDatafilename (char *pIBDatafilename, size_t cbIBDatafilename, tIB_INSTANCEDATA *pIBRand);
extern void              cfgPrintConfig     (tIB_INSTANCEDATA *pIBRand);

#endif // _INCLUDE_LIBIBRAND_CONFIG_H_
