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

#ifndef _INCLUDE_IBRAND_SERVICE_DATASTORE_H_
#define _INCLUDE_IBRAND_SERVICE_DATASTORE_H_

#include "my_utilslib.h"
#include "ibrand_service.h" // For FORCE_ALL_LOGGING_ON
#include "ibrand_service_utils.h"

//#ifdef FORCE_ALL_LOGGING_ON
#ifdef FORCE_ALL_LOGGING_ON_____EXCEPT_THIS
#define FILELOCK_LOGLEVEL 0x02  // 0x01 is stdout, 0x02 is syslog
#else
#define FILELOCK_LOGLEVEL 0x00  // 0x01 is stdout, 0x02 is syslog
#endif

extern bool dataStore_Initialise(tIB_INSTANCEDATA *pIBRand);
extern long dataStore_GetCurrentWaterLevel(tIB_INSTANCEDATA *pIBRand);
extern long dataStore_GetAvailableStorage(tIB_INSTANCEDATA *pIBRand);
extern bool dataStore_Append(tIB_INSTANCEDATA *pIBRand);

#endif // _INCLUDE_IBRAND_SERVICE_DATASTORE_H_
