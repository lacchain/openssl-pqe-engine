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

#ifndef _INCLUDE_IBRAND_SERVICE_H_
#define _INCLUDE_IBRAND_SERVICE_H_

#include <curl/curl.h>
#include "my_utilslib.h"

#include "ibrand_service_config.h" // for tIB_CONFIGDATA

//#define FORCE_ALL_LOGGING_ON

typedef struct tagIB_INSTANCEDATA
{
    tIB_CONFIGDATA cfg;

    // State
    char          szConfigFilename[_MAX_PATH];      //  "/usr/local/ssl/ibrand.cnf"
    int           fCurlInitialised;
    int           fAuthenticated;
    int           fRawOutput;
    CURL *        hCurl;
    char *        pRealToken;
    tLSTRING      Token;
    tLSTRING      ResultantData;
    long          code;
    long          response_code;
    long          datastoreFilesize;
    bool          isPaused;

    // SRNG State
    tLSTRING      encryptedKemSecretKey;
    tLSTRING      ourKemSecretKey;
    //tLSTRING      theirSigningPublicKey;
    tLSTRING      encapsulatedSharedSecret;
    tLSTRING      symmetricSharedSecret;

} tIB_INSTANCEDATA;

typedef enum tagERRORCODE
{
    ERC_AllGood = 0,
    ERC_OopsKemKeyPairExpired = 7010,
    ERC_OopsSharedSecretExpired = 7020,
    ERC_UnspecifiedError = 7999
} tERRORCODE;


#endif // _INCLUDE_IBRAND_SERVICE_H_
