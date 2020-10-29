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
#include "ibrand_service_utils.h"

extern bool dataStore_Initialise(tIB_INSTANCEDATA *pIBRand);
extern long dataStore_GetCurrentWaterLevel(tIB_INSTANCEDATA *pIBRand);
extern long dataStore_GetAvailableStorage(tIB_INSTANCEDATA *pIBRand);
extern bool dataStore_Append(tIB_INSTANCEDATA *pIBRand);

#endif // _INCLUDE_IBRAND_SERVICE_DATASTORE_H_
