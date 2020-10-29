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

#ifndef _INCLUDE_LIBIBRAND_GETNEWENTROPY_H_
#define _INCLUDE_LIBIBRAND_GETNEWENTROPY_H_

#include "libibrand_config.h" // For tIB_INSTANCEDATA
#include "libibrand.h" // For struct ibrand_context

extern bool GetNewEntropy(struct ibrand_context *context, tIB_INSTANCEDATA *pIBRand, uint8_t *inBuf, size_t inBufLen);

#endif // _INCLUDE_LIBIBRAND_GETNEWENTROPY_H_
