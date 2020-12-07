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

#ifndef _INCLUDE_IBRAND_SERVICE_SHMEM_H_
#define _INCLUDE_IBRAND_SERVICE_SHMEM_H_

#include <stddef.h>
#include <stdint.h>

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBSHM_FLOOR 19400
#define ERC_IBSHM_PLACEHOLDER         19410

extern void    ShMem_SetBackingFilename    (char *szBackingFilename);
extern void    ShMem_SetStorageSize        (size_t sizeOfDataStore);
extern void    ShMem_SetSemaphoreName      (char *szSemaphoreName);
extern bool    ShMem_CreateDataStore       (void);
extern bool    ShMem_DestroyDataStore      (void);
extern bool    ShMem_AppendToDataStore     (char *pData, size_t cbData);
extern int32_t ShMem_RetrieveFromDataStore (char *pData, size_t cbData);

extern long    ShMem_GetCurrentWaterLevel  (void);
extern long    ShMem_GetCurrentWaterLevel  (void);
extern long    ShMem_GetTankSize           (void);
extern long    ShMem_GetAvailableStorage   (void);

#endif // _INCLUDE_IBRAND_SERVICE_SHMEM_H_
