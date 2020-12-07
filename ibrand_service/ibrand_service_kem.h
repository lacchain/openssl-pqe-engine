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

#ifndef _INCLUDE_IBRAND_SERVICE_KEM_H_
#define _INCLUDE_IBRAND_SERVICE_KEM_H_

#include "../ibrand_common/my_utilslib.h"
#include "ibrand_service_utils.h"

#include "oqs/kem.h"


extern const char *KemLookupOqsAlgorithmName(int CqcAlgorithmId);
extern bool KemAlgorithmIsValid(const char *algorithmName, bool *pIsSupported, bool *pIsEnabled);
extern int KemDecapsulateSharedSecret(int cqcKemAlgorithmId,
                                      tLSTRING *pSharedSecret,
                                      const tLSTRING *pEncapsulatedSharedSecret,
                                      const tLSTRING *pKemSecretKey);

#endif // _INCLUDE_IBRAND_SERVICE_KEM_H_
