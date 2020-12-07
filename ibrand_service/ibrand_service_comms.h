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

#ifndef _INCLUDE_IBRAND_SERVICE_COMMS_H_
#define _INCLUDE_IBRAND_SERVICE_COMMS_H_

#include <curl/curl.h>

#include "../ibrand_common/my_utilslib.h"
#include "ibrand_service_config.h" // for tIB_CONFIGDATA
#include "ibrand_service.h"

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBCOM_FLOOR 18600
#define ERC_IBCOM_KEMKEYPAIR_EXPIRED                    18610
#define ERC_IBCOM_SHAREDSECRET_EXPIRED                  18620
#define ERC_IBCOM_CURL_INITIALISATION_FAILED            18630
#define ERC_IBCOM_PARAMETER_ERROR_INSTANCE_DATA_IS_NULL 18640
#define ERC_IBCOM_NOMEM_FOR_AUTH_HEADER                 18650
#define ERC_IBCOM_NOENT_CLIENT_CERT_FILE_NOT_FOUND      18660
#define ERC_IBCOM_NOENT_CLIENT_KEY_FILE_NOT_FOUND       18670
#define ERC_IBCOM_OPENSSL_PREFERRED_ENGINE_NOT_SET      18680
#define ERC_IBCOM_AUTH_USER_FAILED                      18690
#define ERC_IBCOM_HTTP_CONNECTION_ERROR                 18700
#define ERC_IBCOM_AUTH_USER_FAILED_WITH_RESPONSECODE    18710
#define ERC_IBCOM_CURL_PERFORM_FAILED                   18740
#define ERC_IBCOM_SET_ENVVAR_FAILED                     18750

extern tERRORCODE CommsInitialise(tIB_INSTANCEDATA *pIBRand);
extern void CommsFinalise(tIB_INSTANCEDATA *pIBRand);

extern tERRORCODE callToRemote(tIB_INSTANCEDATA *pIBRand,
                               const char * pUrl,
                               const char *szEndpoint,
                               bool isAuthenticationCall,
                               size_t (* callbackFunction)(char *buffer, size_t size, size_t nmemb, void *userp),
                               int *pCountRcvdSegments,
                               tLSTRING *pResult,
                               const char *szResultDescription);


#endif // _INCLUDE_IBRAND_SERVICE_COMMS_H_
