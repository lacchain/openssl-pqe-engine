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
#include "../ibrand_common/my_utilslib.h"

#include "ibrand_service_config.h" // for tIB_CONFIGDATA

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
    tLSTRING      authToken;
    tLSTRING      ResultantData;
    int           encryptedRng_RcvdSegments;

    // SRNG State
    tLSTRING      encryptedKemSecretKey;
    int           encryptedKemSecretKey_RcvdSegments;
    tLSTRING      ourKemSecretKey;

    tLSTRING      encapsulatedSharedSecret;
    int           encapsulatedSharedSecret_RcvdSegments;
    tLSTRING      symmetricSharedSecret;

} tIB_INSTANCEDATA;

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBSVC_FLOOR 19800
#define ERC_IBSVC_NOMEM_FOR_URL                           19810
#define ERC_IBSVC_PARAMETER_ERROR_AUTH_URL_NOT_SPECIFIED  19820
#define ERC_IBSVC_PARAMERR_KEM_SECRETKEY_NOT_SPECIFIED    19830
#define ERC_IBSVC_PARAMERR_KEM_SECRETKEY_SIZE_ERROR       19840
#define ERC_IBSVC_PARAMERR_SHARED_SECRET_NOT_SPECIFIED    19850
#define ERC_IBSVC_PARAMERR_SHARED_SECRET_SIZE_ERROR       19860
#define ERC_IBSVC_BASE64_DECODE_FAILURE_OF_SHAREDSECRET   19870
#define ERC_IBSVC_PARAMERR_ENCAP_SHARED_SECRET_SIZE_ERROR 19880
#define ERC_IBSVC_NOMEM_FOR_SHARED_SECRET                 19890
#define ERC_IBSVC_DECAP_OF_SHARED_SECRET_FAILED           19900
#define ERC_IBSVC_REAL_TOKEN_NOT_FOUND                    19910
#define ERC_IBSVC_AUTHTYPE_NOT_SUPPORTED_OR_INVALID       19920


#endif // _INCLUDE_IBRAND_SERVICE_H_
