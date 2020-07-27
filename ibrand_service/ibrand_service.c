///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// Based on the service template provided by Devin Watson:
// http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html
//
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <openssl/aes.h>

#include "../PQCrypto-LWEKE/src/api_frodo640.h"

#define SYSTEM_NAME    "FrodoKEM-640"
#define crypto_kem_keypair            crypto_kem_keypair_Frodo640
#define crypto_kem_enc                crypto_kem_enc_Frodo640
#define crypto_kem_dec                crypto_kem_dec_Frodo640

// int crypto_kem_keypair_Frodo640 (unsigned char *pk, unsigned char *sk);
// int crypto_kem_enc_Frodo640     (unsigned char *ct, unsigned char *ss, const unsigned char *pk);
// int crypto_kem_dec_Frodo640     (unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#include "my_utilslib.h"
#include "IB_SymmetricEncryption.h"


#if LIBCURL_VERSION_NUM < 0x070c03
#error "ERROR - Requires libcurl of 7.12.3 or greater"
#endif

#define RUN_AS_DAEMON

#define CONFIG_HARDCODED 1
#define CONFIG_SIMPLE    2
#define CONFIG_JSON      3
#define USE_CONFIG CONFIG_JSON

#define DBGBIT_STATUS  0
#define DBGBIT_CONFIG  1
#define DBGBIT_AUTH    2
#define DBGBIT_DATA    3
#define DBGBIT_CURL    4
#define DBGBIT_SPARE5  5
#define DBGBIT_SPARE6  6
#define DBGBIT_SPARE7  7

//#define FORCE_ALL_LOGGING_ON

#ifdef FORCE_ALL_LOGGING_ON_____EXCEPT_THIS
#define FILELOCK_LOGLEVEL 0x02  // 0x01 is stdout, 0x02 is syslog
#else
#define FILELOCK_LOGLEVEL 0x00  // 0x01 is stdout, 0x02 is syslog
#endif

typedef struct tagLSTRING
{
    size_t cbData;
    char *pData;
} tLSTRING;

typedef struct tagIB_INSTANCEDATA
{
    // Configuration
    unsigned char  fVerbose;                        // bit 0=general, bit1=config bit2=auth, bit3=data, bit4=curl:
    // Auth
    char          szAuthType[16];                   // "SIMPLE";
    char          szAuthUrl[128];                   // "https://ironbridgeapi.com/login";
    char          szUsername[32];
    char          szPassword[32];
    int           authRetryDelay;
    // Connection
    char          szBaseUrl[128];                   // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    int           bytesPerRequest;                  // Tested with 16 & 256
    int           retrievalRetryDelay;
    // Storage
    char          szStorageType[16];                // "FILE";
    char          szStorageDataFormat[16];          // RAW, BASE64, HEX
    char          szStorageFilename[_MAX_PATH];     // "/var/lib/ibrand/ibrand_data.bin";
    char          szStorageLockfilePath[_MAX_PATH]; // "/tmp";
    long          storageHighWaterMark;             // 1038336; // 1MB
    long          storageLowWaterMark;              // 102400; // 100KB
    int           idleDelay;
    // SRNG Config
    unsigned char useSecureRng;
    char          ourKemSecretKeyFilename[128];
    char          theirSigningPublicKeyFilename[128];

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
    // SRNG State

    tLSTRING      ourKemSecretKey;
    tLSTRING      theirSigningPublicKey;
    tLSTRING      encapsulatedSessionKey;
    tLSTRING      symmetricSessionKey;

} tIB_INSTANCEDATA;

/////////////////////////////////////
// Forward declarations
/////////////////////////////////////
static int DecapsulateAndStoreSessionKey(tIB_INSTANCEDATA *pIBRand);

//-----------------------------------------------------------------------
// ReceiveDataHandler_login
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->Token)
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_login(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pNewData;
    size_t     cbNewData;
    tIB_INSTANCEDATA *pIBRand;

    pNewData  = buffer;
    cbNewData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s Login: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbNewData);

    // Free up the old buffer, if there is one
    if (pIBRand->Token.pData && pIBRand->Token.cbData)
    {
        memset(pIBRand->Token.pData, 0, pIBRand->Token.cbData);
        free(pIBRand->Token.pData);
        pIBRand->Token.pData = NULL;
        pIBRand->Token.cbData = 0;
    }

    // Allocate a new buffer
    pIBRand->Token.pData = (char *)malloc(cbNewData);
    if (pIBRand->Token.pData == NULL)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() malloc failure");
        return 0; // Zero bytes processed
    }

    // Copy in the new data
    memcpy(pIBRand->Token.pData, pNewData, cbNewData);
    pIBRand->Token.cbData = cbNewData;

    //app_tracef("INFO: ReceiveDataHandler_login() Saved %lu bytes", pIBRand->Token.cbData);

    // Job done
    return cbNewData;  // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_rng
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->Token)
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_rng(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pNewData;
    size_t     cbNewData;
    char *     pAllData;
    char *     pExistingData;
    size_t     cbExistingData;
    tIB_INSTANCEDATA *pIBRand;

    pNewData  = buffer;
    cbNewData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_rng() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s request: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbNewData);

    pExistingData  = pIBRand->ResultantData.pData;
    cbExistingData = pIBRand->ResultantData.cbData;
    // If pLString already contains some data (i.e. cbExistingData > 0)
    // then we'll...
    //    a) alloc enough room for both
    //    b) copy in the existing data
    //    c) append our new data to it.

    // Allocate a new buffer
    pAllData = (char *)malloc(cbExistingData + cbNewData);
    if (pAllData == NULL)
    {
        app_tracef("ERROR: ReceiveDataHandler_rng() malloc failure");
        return 0; // Zero bytes processed
    }

    // Copy in the existing data, if there is
    if (cbExistingData && pExistingData)
    {
        memcpy(pAllData, pExistingData, cbExistingData);
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: Appending %u bytes", cbNewData);

    // Copy in the new data
    memcpy(pAllData+cbExistingData, pNewData, cbNewData);

    // Point our userp at the new buffer
    pIBRand->ResultantData.pData = pAllData;
    pIBRand->ResultantData.cbData = cbExistingData + cbNewData;

    // Free up the old buffer, if there is one
    if (cbExistingData && pExistingData)
    {
        free(pExistingData);
        pExistingData = NULL;
        cbExistingData = 0;
    }

    //app_tracef("INFO: ReceiveDataHandler_rng() Saved %lu bytes", pIBRand->ResultantData.cbData);

    // Job done
    return cbNewData; // Number of bytes processed
}


//-----------------------------------------------------------------------
// ReceiveDataHandler_SessionKey
// This is our CURLOPT_WRITEFUNCTION
// and userp is our encapsulatedSessionKey
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_SessionKey(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pInboundKemData;
    size_t     cbInboundKemData;
    tIB_INSTANCEDATA *pIBRand;

    pInboundKemData = buffer;
    cbInboundKemData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s sessionKey: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbInboundKemData);

    // Free up the old buffer, if there is one
    if (pIBRand->encapsulatedSessionKey.pData)
    {
        memset(pIBRand->encapsulatedSessionKey.pData, 0, pIBRand->encapsulatedSessionKey.cbData);
        free(pIBRand->encapsulatedSessionKey.pData);
        pIBRand->encapsulatedSessionKey.pData = NULL;
        pIBRand->encapsulatedSessionKey.cbData = 0;
    }

    // Allocate a new buffer
    pIBRand->encapsulatedSessionKey.pData = (char *)malloc(cbInboundKemData);
    if (pIBRand->encapsulatedSessionKey.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound KEM data");
        return 0; // Zero bytes processed
    }
    memcpy(pIBRand->encapsulatedSessionKey.pData, pInboundKemData, cbInboundKemData);
    // We will set the size once we know it has completed
    pIBRand->encapsulatedSessionKey.cbData = cbInboundKemData;

    // Destroy any existing session key, forcing the new one to be decapsulated and used as and when needed.
    if (pIBRand->symmetricSessionKey.pData)
    {
        memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
        free(pIBRand->symmetricSessionKey.pData);
        pIBRand->symmetricSessionKey.pData = NULL;
        pIBRand->symmetricSessionKey.cbData = 0;
    }

    app_tracef("INFO: KEM data stored successfully (%lu bytes)", pIBRand->encapsulatedSessionKey.cbData);

    // Job done
    return cbInboundKemData; // Number of bytes processed
}


//-----------------------------------------------------------------------
// DecapsulateAndStoreSessionKey
//-----------------------------------------------------------------------
static int DecapsulateAndStoreSessionKey(tIB_INSTANCEDATA *pIBRand)
{
    // If there is already a session key stored, then clear and free it.
    if (pIBRand->symmetricSessionKey.pData)
    {
        memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
        free(pIBRand->symmetricSessionKey.pData);
        pIBRand->symmetricSessionKey.pData = NULL;
        pIBRand->symmetricSessionKey.cbData = 0;
    }

    // Check that we have the secret Key needed for the KEM decapsulation
    if (!pIBRand->ourKemSecretKey.pData || pIBRand->ourKemSecretKey.cbData != CRYPTO_SECRETKEYBYTES)
    {
        app_tracef("ERROR: Size of secret key is not as expected");
        return 2201;
    }
    // Check that we have the encapsulated key
    if (!pIBRand->encapsulatedSessionKey.pData || pIBRand->encapsulatedSessionKey.cbData == 0)
    {
        app_tracef("ERROR: Encapsulated session key not found");
        return 2202;
    }

    unsigned char *p = (unsigned char *)pIBRand->encapsulatedSessionKey.pData;
    size_t n = pIBRand->encapsulatedSessionKey.cbData;
    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_A_quoted_base64_encapsulated_key.txt", p, n);

    //app_trace_hexall("DEBUG: base64 encoded encapsulatedSessionKey:", pIBRand->encapsulatedSessionKey.pData, pIBRand->encapsulatedSessionKey.cbData);
    if (p[0] == '"') {p++; n--;}
    if (p[n-1] == '"') {n--;}
    //app_trace_hexall("DEBUG: p:", p, n);
    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_B_base64_encapsulated_key.txt", p, n);

    // base64_decode the encapsulate key
    size_t decodeSize = 0;
    unsigned char *rawEncapsulatedKey = base64_decode((char *)p, n, (size_t *)&(decodeSize));
    if (!rawEncapsulatedKey)
    {
       app_tracef("WARNING: Failed to decode Base64 EncapsulatedKey");
       return 2299;
    }
    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_C_encapsulated_key.txt", rawEncapsulatedKey, decodeSize);

    if (decodeSize != CRYPTO_CIPHERTEXTBYTES)
    {
        app_tracef("ERROR: Size of decoded encapsulated key (%u) is not as expected (%u)", decodeSize, CRYPTO_CIPHERTEXTBYTES);
        //app_trace_hexall("DEBUG: encapsulatedSessionKey:", (char *)rawEncapsulatedKey, decodeSize);
        return 2203;
    }

    // Allocate a new buffer
    pIBRand->symmetricSessionKey.pData = (char *)malloc(CRYPTO_BYTES);
    if (pIBRand->symmetricSessionKey.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for new session key");
        return 2204;
    }
    // Initialise with something recognisable, so that we can ensure that it has worked
    memset(pIBRand->symmetricSessionKey.pData, 0xAA, CRYPTO_BYTES);

    // Do the KEM decapsulation
    crypto_kem_dec((unsigned char *)pIBRand->symmetricSessionKey.pData, (unsigned char *)rawEncapsulatedKey, (unsigned char *)pIBRand->ourKemSecretKey.pData);

    // We will set the size once we know it has completed
    pIBRand->symmetricSessionKey.cbData = CRYPTO_BYTES;

    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_D_raw.txt", (unsigned char *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData);
    app_tracef("INFO: Session key stored successfully (%lu bytes)", pIBRand->symmetricSessionKey.cbData);

    // Job done
    return 0;
}


//-----------------------------------------------------------------------
// authenticateUser
//-----------------------------------------------------------------------
int authenticateUser(tIB_INSTANCEDATA *pIBRand)
{
    if (!pIBRand)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - instance data is null");
        return 2210;
    }

    if (strlen(pIBRand->szAuthUrl) == 0)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - AuthUrl is empty");
        return 2211;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: authenticateUser: (\"%s\", \"%s\", \"%s\")", pIBRand->szAuthUrl, pIBRand->szUsername, pIBRand->szPassword);
    }
    else
    {
        app_tracef("INFO: Authenticating User: (\"%s\", \"%s\")", pIBRand->szAuthUrl, pIBRand->szUsername);
    }

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pIBRand->szAuthUrl);
//#define USE_CORRECT_ENGINE
#ifdef USE_CORRECT_ENGINE
    // Anything except ourselves.
    // Ideally: RAND_set_rand_engine(NULL)
    //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, "dynamic");
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: Force use of alternate OpenSSL RNG engine");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, "rdrand");
    //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, NULL);
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: CURLOPT_SSLENGINE_DEFAULT");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE_DEFAULT, 1L);
#endif // USE_CORRECT_ENGINE

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
    //    app_tracef("INFO: Construct HTTP Headers");
    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Authorization: Bearer" );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);

    char bodyData[1024] = "";
    //sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", pIBRand->szUsername, pIBRand->szPassword );
    // sending a a, as we don't need to send this with a client certificate
    sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", "a", "a" );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_POSTFIELDS, bodyData);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_login);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    // adding client cert
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT, "/etc/ssl/certs/client_cert.pem"); //load cert
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, "PEM");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY, "/etc/ssl/private/client_key.pem"); // load key

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: Connecting to \"%s\" with \"%s\"", pIBRand->szAuthUrl, bodyData);
    }

    /* Do it */
    CURLcode      curlResultCodeA;
    curlResultCodeA = curl_easy_perform(pIBRand->hCurl);
    if (curlResultCodeA != CURLE_OK)
    {
      app_tracef("ERROR: authenticateUser failed: rc=%d (%s)", curlResultCodeA, curl_easy_strerror(curlResultCodeA));
      return 2212;
    }

    pIBRand->code = 0;
    CURLcode curlResultCodeB;
    curlResultCodeB = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_HTTP_CONNECTCODE, &pIBRand->code);
    if (!curlResultCodeB && pIBRand->code)
    {
        app_tracef("ERROR: authenticateUser: ResultCode=%03ld (%s)", pIBRand->code, curl_easy_strerror(pIBRand->code));
        return 2220;
    }

    pIBRand->response_code = 0;
    CURLcode  curlResultCodeC;
    curlResultCodeC = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &pIBRand->response_code);
    if (!curlResultCodeC && (pIBRand->response_code != 200))
    {
        app_tracef("ERROR: authenticateUser: HTTP Responcse Code=%ld", pIBRand->response_code);
        return 2221;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: authenticateUser() Token = [%s]"            , pIBRand->Token.pData);
    }

    curl_slist_free_all(headers); /* free custom header list */
    app_tracef("INFO: Authentication successful: (\"%s\", \"%s\")", pIBRand->szAuthUrl, pIBRand->szUsername);
    return 0;
}

//-----------------------------------------------------------------------
// getRandomBytes
//-----------------------------------------------------------------------
int getRandomBytes(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char * szEndpoint;
    #define MAXUINT_DIGITS 20 // 0x7FFF FFFF FFFF FFFF = 9,223,372,036,854,775,807 ==> 19 digits for signed, 20 for unsigned.

    if (pIBRand->useSecureRng)
    {
        szEndpoint = "srng";
    }
    else
    {
        szEndpoint = "rng";
    }

    pUrl = (char *)malloc(strlen(pIBRand->szBaseUrl)+strlen(szEndpoint)+2+MAXUINT_DIGITS); // i.e. strlen("/rng/NNNNNNN")
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 22230;
    }
    sprintf(pUrl,"%s/%s/%u", pIBRand->szBaseUrl, szEndpoint, pIBRand->bytesPerRequest);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    char *pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
    if (!pAuthHeader)
    {
        app_tracef("ERROR: Out of memory allocating for AuthHeader");
        return 2231;
    }
    sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: %s AuthHeader = \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pAuthHeader);
    }

    headers = curl_slist_append ( headers, pAuthHeader );

    // e.g.
    //   "name": "accept",
    //   "value": "application/json, text/plain, */*"
    //   "name": "authorization",
    //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
    //   "name": "content-type",
    //   "value": "application/json"

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_rng);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    // Do it
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s response code = %ld", pIBRand->useSecureRng?"SRNG":"RNG", httpResponseCode);
    }

    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: %s perform failed: [%s]", pIBRand->useSecureRng?"SRNG":"RNG", curl_easy_strerror(curlResultCode));
        return 2232;
    }

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    curl_slist_free_all(headers); /* free custom header list */
    free(pAuthHeader);
    free(pUrl);
    return 0;
}

//-----------------------------------------------------------------------
// getSecureRNGSessionKey
//-----------------------------------------------------------------------
int getSecureRNGSessionKey(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char *szEndpoint = "sharedsecret";

    pUrl = (char *)malloc(strlen(pIBRand->szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->szBaseUrl, szEndpoint);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    char *pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
    if (!pAuthHeader)
    {
        app_tracef("ERROR: Out of memory allocating for AuthHeader");
        return 2241;
    }
    sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: %s AuthHeader = \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pAuthHeader);
    }

    headers = curl_slist_append ( headers, pAuthHeader );

    // e.g.
    //   "name": "accept",
    //   "value": "application/json, text/plain, */*"
    //   "name": "authorization",
    //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
    //   "name": "content-type",
    //   "value": "application/json"

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_SessionKey);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);

    /* Do it */
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: %s perform failed: [%s]", pIBRand->useSecureRng?"SRNG":"RNG", curl_easy_strerror(curlResultCode));
        return 2242;
    }

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    curl_slist_free_all(headers); /* free custom header list */
    free(pAuthHeader);
    free(pUrl);
    return 0;
}


//-----------------------------------------------------------------------
// storeRandomBytes
//-----------------------------------------------------------------------
void storeRandomBytes(tIB_INSTANCEDATA *pIBRand)
{
    if (pIBRand->ResultantData.pData == NULL || pIBRand->ResultantData.cbData == 0)
    {
        // Nothing to do
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: Nothing to do. [pData=%p, cbData=%u]", pIBRand->ResultantData.pData, pIBRand->ResultantData.cbData);
        }
        return;
    }

    if (pIBRand->useSecureRng)
    {
        // The data is currently Base64 encoded encrypted data
        ///////////////////////////////////
        // DeBase64 the data...
        ///////////////////////////////////
        char * pOriginalData  = pIBRand->ResultantData.pData;
        size_t cbOriginalData = pIBRand->ResultantData.cbData;

        //dumpToFile("/home/jgilmore/dev/dump_SRNG_A_quoted_base64_encrypted_data.txt", (unsigned char *)pIBRand->ResultantData.pData, pIBRand->ResultantData.cbData);

        char * pDecodeData = pOriginalData;
        size_t cbDecodeData = cbOriginalData;
        if (pOriginalData[0] == '"' && pOriginalData[cbOriginalData-1] == '"')
        {
            pDecodeData = pOriginalData + 1;
            cbDecodeData = cbOriginalData - 2;
        }
        else
        {
            pDecodeData = pOriginalData;
            cbDecodeData = cbOriginalData;
        }
        //dumpToFile("/home/jgilmore/dev/dump_SRNG_B_base64_encrypted_data.txt", (unsigned char *)pDecodeData, cbDecodeData);
        size_t cbEncryptedData = 0;
        unsigned char *pEncryptedData = base64_decode(pDecodeData, cbDecodeData, &cbEncryptedData);
        if (!pEncryptedData)
        {
           app_tracef("WARNING: Failed to decode Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
           return;
        }
        free(pIBRand->ResultantData.pData);
        pIBRand->ResultantData.pData = NULL;
        pIBRand->ResultantData.cbData = 0;

        //dumpToFile("/home/jgilmore/dev/dump_SRNG_C_encrypted_data.txt", pEncryptedData, cbEncryptedData);
        ///////////////////////////////////
        // Decrypt the data...
        ///////////////////////////////////
        if (pIBRand->symmetricSessionKey.pData==NULL)
        {
            if (pIBRand->encapsulatedSessionKey.pData==NULL)
            {
                // No keys found
                app_tracef("ERROR: No session key available to decryption SRNG response");
                return; // todo cleanup
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                app_tracef("INFO: Decapsulating session key");
            int rc = DecapsulateAndStoreSessionKey(pIBRand);
            if (rc != 0)
            {
                app_tracef("ERROR: KEM decapsulation failed with rc=%d", rc);
                return; // todo cleanup
            }
        }
#define USE_PBKDF2
#ifdef USE_PBKDF2
        unsigned char *pDecryptedData = NULL;
        size_t         cbDecryptedData = 0;
        int rc;

        rc = AESDecryptBytes(pEncryptedData, cbEncryptedData, (uint8_t *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData, 32, &pDecryptedData, &cbDecryptedData);
        if (rc)
        {
            printf("AESDecryptBytes failed with rc=%d\n", rc);
        }
        pIBRand->ResultantData.pData = (char *)pDecryptedData;
        pIBRand->ResultantData.cbData = cbDecryptedData;
#else
        // Initialisation vector
        unsigned char iv[AES_BLOCK_SIZE];
        AES_KEY dec_key;

        // AES-128 bit CBC Decryption
        memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly

        // Rfc2898DeriveBytes
        // Crypto::Rfc2898DeriveBytes   derivedBytes(key, saltSize);
        // auto                         salt       = derivedBytes.salt();
        // auto                         keyBytes   = derivedBytes.getBytes(32);
        // auto                         ivBytes    = derivedBytes.getBytes(16);

        // We have a key
        // We have an IV
        // We have some data
        // Let's do it.

        AES_set_decrypt_key((unsigned char *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData*8, &dec_key); // Size of key is in bits
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
            app_tracef("INFO: Decrypting %u bytes", pIBRand->symmetricSessionKey.cbData);
        unsigned char *pRawData = (unsigned char *)malloc(cbEncryptedData);
        if (!pRawData)
        {
            app_tracef("ERROR: Malloc for decrypted data failed");
            return; // todo cleanup
        }
        AES_cbc_encrypt(pEncryptedData, pRawData, cbEncryptedData, &dec_key, iv, AES_DECRYPT);
        size_t cbRawData = cbEncryptedData;

        free(pEncryptedData);
        pEncryptedData = NULL;
        cbEncryptedData = 0;

        pIBRand->ResultantData.pData = (char *)pRawData;
        pIBRand->ResultantData.cbData = cbRawData;
#endif
        //dumpToFile("/home/jgilmore/dev/dump_SRNG_D_raw_data.txt", (uint8_t *)pIBRand->ResultantData.pData, (size_t)pIBRand->ResultantData.cbData);

        // The data is now raw data
        if (strcmp(pIBRand->szStorageDataFormat,"RAW")!=0)
        {
            app_tracef("WARNING: Only RAW format is supported for SRNG. Discarding %u bytes.", pIBRand->ResultantData.cbData);
            return; // todo cleanup
        }
    }
    else // RNG
    {
        // The data is currently Base64 encoded raw data

        // Format the output data
        if (strcmp(pIBRand->szStorageDataFormat,"RAW")==0)
        {
            // Curl_base64_decode() - Given a base64 string at src, decode it and return
            // an allocated memory in the *outptr. Returns the length of the decoded data.
            //*pcbData = Curl_base64_decode(p, (unsigned char **)ppData)
            // *ppData will, and must, be freed by the caller

            //dumpToFile("/home/jgilmore/dev/dump_Data_A_base64_encrypted_data.txt", p, n);

            //app_tracef("INFO: %s ResultantData[%u] = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
            char * pOriginalData  = pIBRand->ResultantData.pData;
            size_t cbOriginalData = pIBRand->ResultantData.cbData;

            char * pDecodeData = pOriginalData;
            size_t cbDecodeData = cbOriginalData;
            if (pOriginalData[0] == '"' && pOriginalData[cbOriginalData-1] == '"')
            {
                pDecodeData = pOriginalData + 1;
                cbDecodeData = cbOriginalData - 2;
            }
            else
            {
                pDecodeData = pOriginalData;
                cbDecodeData = cbOriginalData;
            }

            // Debugging Begin
            {
                //char *p = pDecodeData;
                //size_t n = cbDecodeData;
                //dumpToFile("/home/jgilmore/dev/dump_Data_A_base64_encrypted_data.txt", (unsigned char *)p, n);
                //app_trace_hexall("DEBUG: base64 encoded data:", p, n);
            }
            // Debugging End

            pIBRand->ResultantData.pData = (char *)base64_decode(pDecodeData, cbDecodeData, (size_t *)&(pIBRand->ResultantData.cbData));
            if (!pIBRand->ResultantData.pData)
            {
               app_tracef("WARNING: Failed to decode Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
               return;
            }
            free(pOriginalData);
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
            {
                app_tracef("INFO: %s ResultantData[%u]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData);
                //app_tracef("INFO: %s ResultantData[%u] = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
            }
        }
        else if (strcmp(pIBRand->szStorageDataFormat,"BASE64")==0)
        {
            // Nothing to do. The data is already Base64 encoded

            // The data may be wrapped in double-quotes, which will need removing
            char * pOriginalData  = pIBRand->ResultantData.pData;
            size_t cbOriginalData = pIBRand->ResultantData.cbData;

            if (pOriginalData[0] == '"' && pOriginalData[cbOriginalData-1] == '"')
            {
                // Alloc a new, smaller buffer, copy the data in, and free up the original buffer.
                // Not the most efficient, but simple - for now.
                pIBRand->ResultantData.cbData = cbOriginalData - 2;
                pIBRand->ResultantData.pData = malloc(pIBRand->ResultantData.cbData);
                if (!pIBRand->ResultantData.pData)
                {
                    app_tracef("WARNING: Failed to clean Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
                    pIBRand->ResultantData.pData = pOriginalData;
                    pIBRand->ResultantData.cbData = cbOriginalData;
                    return;
                }
                memcpy(pIBRand->ResultantData.pData, pOriginalData+1, pIBRand->ResultantData.cbData);
                free(pOriginalData);
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
            {
                app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
            }
        }
        else if (strcmp(pIBRand->szStorageDataFormat,"HEX")==0)
        {
            // TODO
            app_tracef("WARNING: Storage data format \"%s\"  not yet implemented. Discarding %u bytes.", pIBRand->szStorageDataFormat, pIBRand->ResultantData.cbData);
            return;
        }
        else
        {
            app_tracef("WARNING: Unsupported storage data format \"%s\". Discarding %u bytes.", pIBRand->szStorageDataFormat, pIBRand->ResultantData.cbData);
            return;
        }
    } // RNG


    if (strcmp(pIBRand->szStorageType,"FILE")==0)
    {
        //fprintf(stdout, "%u:%s\n", pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
        FILE *f;
        unsigned int bytesWritten1 = 0;
        unsigned int bytesWritten2 = 0;

        my_waitForFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
        f = fopen(pIBRand->szStorageFilename,"ab");
        if (!f)
        {
            app_tracef("WARNING: Unable to open storage file. Discarding %u bytes.", pIBRand->ResultantData.cbData);
            my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
            // ...and sleep a little in the hope that it will recover
            sleep(1);
            return;
        }
        bytesWritten1 = fwrite(pIBRand->ResultantData.pData, 1, pIBRand->ResultantData.cbData, f);
        if (bytesWritten1 != pIBRand->ResultantData.cbData)
        {
            app_tracef("WARNING: Unable to write all bytes (%d/%d)", bytesWritten1, pIBRand->ResultantData.cbData);
        }
        // Delimit each Base64 block with a LF
        if (strcmp(pIBRand->szStorageDataFormat,"BASE64")==0)
        {
            bytesWritten2 = fwrite("\n", 1, 1, f);
            if (bytesWritten2 != 1)
            {
                app_tracef("WARNING: Unable to write LF");
            }
        }
        fclose(f);
        my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: %s %u+%u bytes stored", pIBRand->useSecureRng?"SRNG":"RNG", bytesWritten1, bytesWritten2);
        }
    }
    else
    {
        app_tracef("WARNING: Unsupported storage type \"%s\". Discarding %u bytes.", pIBRand->szStorageType, pIBRand->ResultantData.cbData);
        return;
    }
}

//-----------------------------------------------------------------------
// ExtractSubstring
//-----------------------------------------------------------------------
char *ExtractSubstring(char *pTokenData, const char *pPrefix, const char *pSuffix)
{
    char *pSubstring;
    int substringLen;
    char *p1 = strstr(pTokenData, pPrefix );
    if (!p1)
    {
        //app_tracef("WARNING: ExtractSubstring() Cannot find token in \"%s\"", pTokenData);
        return NULL;
    }
    p1 += strlen(pPrefix);
    // p1 now points to the start of the substring

    char *p2 = strstr(p1, pSuffix );
    if (!p2)
    {
        app_tracef("WARNING: ExtractSubstring() Cannot find end of token in \"%s\"", pTokenData);
        return NULL;
    }
    // p1 now points to the first character following the substring
    substringLen = p2-p1;

    pSubstring = (char *)malloc(substringLen+1);
    if (!pSubstring)
    {
        app_tracef("ERROR: ExtractSubstring() malloc error");
        return NULL;
    }
    memcpy(pSubstring,p1,substringLen);
    pSubstring[substringLen] = 0;

    return pSubstring;
}

//-----------------------------------------------------------------------
// validateSettings
//-----------------------------------------------------------------------
int validateSettings(tIB_INSTANCEDATA *pIBRand)
{
    if (strlen(pIBRand->szUsername) == 0)
    {
        app_tracef("ERROR: Username is mandatory, but not supplied. Aborting.");
        return 2250;
    }
    if (strlen(pIBRand->szPassword) == 0)
    {
        app_tracef("ERROR: Password is mandatory, but not supplied. Aborting.");
        return 2251;
    }
    if (strlen(pIBRand->szBaseUrl) == 0)
    {
        // Parameter error
        app_tracef("ERROR: URL is mandatory, but not supplied. Aborting.");
        return 2252;
    }
    return 0;
}

//-----------------------------------------------------------------------
// InitialiseCurl
//-----------------------------------------------------------------------
int InitialiseCurl(tIB_INSTANCEDATA *pIBRand)
{
    //////////////////////////////
    // Initialise libcurl
    //////////////////////////////
    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    pIBRand->hCurl = curl_easy_init();
    if (!pIBRand->hCurl)
    {
      app_tracef("ERROR: Library initialisation failed");
      return 2260;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
    {
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_TIMEOUT, xxx);
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);


        // CURLOPT_STDERR must be set to something specific.
        // Setting curl_setopt($c, CURLOPT_STDERR, fopen('/curl.txt', 'w+')); fixed my issue.
        // As it turns out curl_setopt($c, CURLOPT_VERBOSE, 1); is not printing the output to STDERR for some reason which I have not uncovered. I did not find the output in any of my PHP, Apache, nor Event Viewer logs.
        // After setting curl_setopt($c, CURLOPT_STDERR, fopen('/curl.txt', 'w+'));, I was able to see the output in the curl.txt file.
        // I am not sure if this is specific to Windows environments.
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_STDERR, fopen('/curl.txt', 'w+'));

        curl_easy_setopt(pIBRand->hCurl, CURLOPT_VERBOSE, 1L);
        /*
            typedef enum
            {
              CURLINFO_TEXT = 0,
              CURLINFO_HEADER_IN,    // 1
              CURLINFO_HEADER_OUT,   // 2
              CURLINFO_DATA_IN,      // 3
              CURLINFO_DATA_OUT,     // 4
              CURLINFO_SSL_DATA_IN,  // 5
              CURLINFO_SSL_DATA_OUT, // 6
              CURLINFO_END
            } tCURL_INFOTYPE;

            int CurlDebugCallback(CURL *handle, tCURL_INFOTYPE type, char *data, size_t size, void *userptr)
            {
            }
            CURLcode curl_easy_setopt(pIBRand->hCurl, CURLOPT_DEBUGFUNCTION, CurlDebugCallback);
            CURLcode curl_easy_setopt(pIBRand->hCurl, CURLOPT_DEBUGDATA, pIBRand); // JG: Does this call exist - i.e. does CURLOPT_DEBUGFUNCTION have userdata?
        */
    }

    pIBRand->fCurlInitialised = TRUE;
    return 0;
}

//-----------------------------------------------------------------------
// DoAuthentication
//-----------------------------------------------------------------------
int DoAuthentication(tIB_INSTANCEDATA *pIBRand)
{
    int rc;

    //////////////////////////////
    // Authenticate the user
    //////////////////////////////
    pIBRand->Token.pData = NULL;
    pIBRand->Token.cbData = 0;
    rc = authenticateUser ( pIBRand );
    if (rc != 0)
    {
      app_tracef("ERROR: authenticateUser failed rc=%d", rc);
      return rc; // 2200..2299
    }

    // TokenData is something of the form (without the EOLs)...
    // {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTc1MzgzOTI5LCJleHAiOjE1NzU0NzAzMjksImlhdCI6MTU3NTM4MzkyOSwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.DvrJew9dLYVgmzB36N8LgRT1zT4hJsDtr0pjG_8WJBs",
    //  "notBefore":"2019-12-03T14:38:49.10979Z",
    //  "notAfter":"2019-12-04T14:38:49.10979Z"}

    // Todo: Use strtok or regex or similar
    pIBRand->pRealToken = ExtractSubstring(pIBRand->Token.pData, "\"token\":\"", "\"");
    if (!pIBRand->pRealToken)
    {
        // Check with space after colon
        pIBRand->pRealToken = ExtractSubstring(pIBRand->Token.pData, "\"token\": \"", "\"");
        if (!pIBRand->pRealToken)
        {
          app_tracef("ERROR: Cannot find token in TokenData pData=[%s]", pIBRand->Token.pData);
          return 2270;
        }
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: pRealToken = [%s]", pIBRand->pRealToken);
    }

    //fprintf(stderr, "DEBUG: Token.pData=[%s]\n", pIBRand->Token.pData);
    //fprintf(stderr, "DEBUG: pRealToken=[%s]\n", pIBRand->pRealToken);

    pIBRand->fAuthenticated = TRUE;

    return 0;
}

//-----------------------------------------------------------------------
// ironbridge_api_finalise
//-----------------------------------------------------------------------
void ironbridge_api_finalise(tIB_INSTANCEDATA *pIBRand)
{
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: ironbridge_api_finalise()");

    //////////////////////////////
    // Cleanup and wipe away our footprints
    //////////////////////////////
    if (pIBRand->pRealToken)
    {
        memset(pIBRand->pRealToken, 0, strlen(pIBRand->pRealToken));
        free(pIBRand->pRealToken);
        pIBRand->pRealToken = NULL;
    }
    if (pIBRand->ResultantData.pData)
    {
        memset(pIBRand->ResultantData.pData, 0, pIBRand->ResultantData.cbData);
        free(pIBRand->ResultantData.pData);
        pIBRand->ResultantData.cbData = 0;
        pIBRand->ResultantData.pData = NULL;
    }
    if (pIBRand->Token.pData)
    {
        memset(pIBRand->Token.pData, 0, pIBRand->Token.cbData);
        free(pIBRand->Token.pData);
        pIBRand->Token.cbData = 0;
        pIBRand->Token.pData = NULL;
    }
    if (pIBRand->symmetricSessionKey.pData)
    {
        memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
        free(pIBRand->symmetricSessionKey.pData);
        pIBRand->symmetricSessionKey.cbData = 0;
        pIBRand->symmetricSessionKey.pData = NULL;
    }
    if (pIBRand->ourKemSecretKey.pData)
    {
        memset(pIBRand->ourKemSecretKey.pData, 0, pIBRand->ourKemSecretKey.cbData);
        free(pIBRand->ourKemSecretKey.pData);
        pIBRand->ourKemSecretKey.cbData = 0;
        pIBRand->ourKemSecretKey.pData = NULL;
    }
    if (pIBRand->theirSigningPublicKey.pData)
    {
        memset(pIBRand->theirSigningPublicKey.pData, 0, pIBRand->theirSigningPublicKey.cbData);
        free(pIBRand->theirSigningPublicKey.pData);
        pIBRand->theirSigningPublicKey.cbData = 0;
        pIBRand->theirSigningPublicKey.pData = NULL;
    }
    curl_easy_cleanup(pIBRand->hCurl);
    curl_global_cleanup();

    if (pIBRand)
    {
        // Destory contents and free
        memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));
        free(pIBRand);
    }
}

//-----------------------------------------------------------------------
// ReadConfig
//-----------------------------------------------------------------------
static int ReadContentsOfFile(char *szFilename, tLSTRING *pDest, size_t expectedNumberOfBytes)
{
    if (szFilename == NULL || strlen(szFilename) == 0)
    {
        app_tracef("ERROR: Cannot read the contents of a file with no name");
        return 2280;
    }

    if (!my_fileExists(szFilename))
    {
        app_tracef("ERROR: File not found: \"%s\"", szFilename);
        return 2281;
    }

    size_t filesize = my_getFilesize(szFilename);
    if (filesize != expectedNumberOfBytes)
    {
        app_tracef("ERROR: Size of file (%s, %u bytes) is not as expected (%u bytes)", szFilename, filesize, expectedNumberOfBytes);
        return 2282;
    }
    pDest->pData = malloc(filesize);
    if (!pDest->pData)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for file contents", filesize);
        return 2283;
    }

    FILE *fIn = fopen(szFilename, "rb");
    if (!fIn)
    {
        app_tracef("ERROR: Failed to open input file: \"%s\"", szFilename);
        memset(pDest->pData, 0, filesize);
        free(pDest->pData);
        pDest->pData = NULL;
        pDest->cbData = 0;
        return 2284;
    }
    size_t bytesRead = fread(pDest->pData, 1, filesize, fIn);
    if (bytesRead != filesize)
    {
        app_tracef("ERROR: Failed to read key from file: \"%s\"", szFilename);
        fclose(fIn);
        memset(pDest->pData, 0, filesize);
        free(pDest->pData);
        pDest->pData = NULL;
        pDest->cbData = 0;
        return 2285;
    }
    pDest->cbData = bytesRead;
    fclose(fIn);

    return 0;
}

#if (USE_CONFIG==CONFIG_HARDCODED)
static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    int rc;
    if (!pIBRand)
    {
        return 2290;
    }

    UNUSED_PARAM(szConfigFilename);

    app_tracef("WARNING: Configuration from hardcode values");

    //////////////////////////////////////
    // Hardcoded values for testing
    /////////////////////////////////////
    strcpy(pIBRand->szAuthType            , "SIMPLE");
    strcpy(pIBRand->szAuthUrl             , "ironbridgeapi.com/api/login");
    strcpy(pIBRand->szUsername            , "Fred");
    strcpy(pIBRand->szPassword            , "Pa55w0rd");
    pIBRand->authRetryDelay               = 15;

    strcpy(pIBRand->szBaseUrl             , "ironbridgeapi.com/api");
    pIBRand->bytesPerRequest              = 16;
    pIBRand->retrievalRetryDelay          = 3;

    strcpy(pIBRand->szStorageType         , "FILE");
    strcpy(pIBRand->szStorageDataFormat   , "RAW"); // "RAW", "BASE64", "HEX" (todo)
    strcpy(pIBRand->szStorageFilename     , "/var/lib/ibrand/ibrand_data.bin");
    strcpy(pIBRand->szStorageLockfilePath , "/tmp");
    pIBRand->storageHighWaterMark         = 102400; // 1038336; // 1MB
    pIBRand->storageLowWaterMark          = 10240; // 102400; // 100KB
    pIBRand->idleDelay                    = 10;

    pIBRand->useSecureRng                 = true;
    pIBRand->ourKemSecretKeyFilename      = "";
    pIBRand->theirSigningPublicKeyFilename= "";

    pIBRand->ourKemSecretKey.pData        = NULL;
    pIBRand->ourKemSecretKey.cbData       = 0;
    pIBRand->theirSigningPublicKey.pData  = NULL;
    pIBRand->theirSigningPublicKey.cbData = 0;

    //pIBRand->fVerbose                     = 0x03;
    SET_BIT(pIBRand->fVerbose, DBGBIT_STATUS );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CONFIG );
    SET_BIT(pIBRand->fVerbose, DBGBIT_AUTH   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_DATA   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CURL   );

    rc = validateSettings(pIBRand);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }
    return 0;
}
#elif (USE_CONFIG==CONFIG_SIMPLE)
static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    int rc;
    if (!pIBRand)
    {
        return 2300;
    }

    //////////////////////////////////////
    // Get values from config file
    /////////////////////////////////////
    char *szFilename;
    FILE *hConfigFile;

    rc = my_openSimpleConfigFile(szConfigFilename, &hConfigFile);
    if (rc)
    {
        app_tracef("ERROR: OpenConfigFile error %d", rc);
        return rc;
    }
    app_tracef("INFO: Configuration file (SIMPLE format) [%s]", szConfigFilename);
    if (hConfigFile)
    {
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHTYPE"                     , pIBRand->szAuthType            , sizeof(pIBRand->szAuthType           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHTYPE"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "SIMPLE"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHURL"                      , pIBRand->szAuthUrl             , sizeof(pIBRand->szAuthUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHURL"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "https://ironbridgeapi.com/login"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHUSER"                     , pIBRand->szUsername            , sizeof(pIBRand->szUsername           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHUSER"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Pa55w0rd"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHPSWD"                     , pIBRand->szPassword            , sizeof(pIBRand->szPassword           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHPSWD"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Username"
        rc = my_readSimpleConfigFileInt (hConfigFile, "AUTHRETRYDELAY"               , &pIBRand->authRetryDelay                                                ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHRETRYDELAY"               , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "BASEURL"                      , pIBRand->szBaseUrl             , sizeof(pIBRand->szBaseUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BASEURL"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "ironbridgeapi.com/api" or "192.168.9.128:6502/v1/ironbridge/api"
        rc = my_readSimpleConfigFileInt (hConfigFile, "BYTESPERREQUEST"              , &pIBRand->bytesPerRequest                                               ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BYTESPERREQUEST"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 16;
        rc = my_readSimpleConfigFileInt (hConfigFile, "RETRIEVALRETRYDELAY"          , &pIBRand->retrievalRetryDelay                                           ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "RETRIEVALRETRYDELAY"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGETYPE"                  , pIBRand->szStorageType         , sizeof(pIBRand->szStorageType        ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGETYPE"                  , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. FILE, MEMORY, MYSQL etc
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEDATAFORMAT"            , pIBRand->szStorageDataFormat   , sizeof(pIBRand->szStorageDataFormat  ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEDATAFORMAT"            , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. RAW, BASE64, HEX
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEFILENAME"              , pIBRand->szStorageFilename     , sizeof(pIBRand->szStorageFilename    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEFILENAME"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/var/lib/ibrand/ibrand_data.bin"
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGELOCKFILEPATH"          , pIBRand->szStorageLockfilePath , sizeof(pIBRand->szStorageLockfilePath) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOCKFILEPATH"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/tmp"
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGEHIGHWATERMARK"         , &pIBRand->storageHighWaterMark                                          ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEHIGHWATERMARK"         , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 1038336 (1MB)
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGELOWWATERMARK"          , &pIBRand->storageLowWaterMark                                           ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOWWATERMARK"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 102400 (100KB)
        rc = my_readSimpleConfigFileInt (hConfigFile, "IDLEDELAY"                    , &pIBRand->idleDelay                                                     ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "IDLEDELAY"                    , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileByte(hConfigFile, "VERBOSE"                      , &pIBRand->fVerbose                                                      ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "VERBOSE"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        rc = my_readSimpleConfigFileByte(hConfigFile, "USESECURERNG"                 , &pIBRand->useSecureRng                                                  ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "USESECURERNG"                 , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        rc = my_readSimpleConfigFileStr (hConfigFile, "OURKEMSECRETKEYFILENAME"      , pIBRand->ourKemSecretKeyFilename                                        ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "OURKEMSECRETKEYFILENAME"      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; }
        rc = my_readSimpleConfigFileStr (hConfigFile, "THEIRSIGNINGPUBLICKEYFILENAME", pIBRand->theirSigningPublicKeyFilename                                  ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "THEIRSIGNINGPUBLICKEYFILENAME", rc); my_closeSimpleConfigFile(hConfigFile); return rc; }

        my_closeSimpleConfigFile(hConfigFile);
    }

    rc = validateSettings(pIBRand);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }
    return 0;
}
#elif (USE_CONFIG==CONFIG_JSON)
////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_INSTANCEDATA *pIBRand)
{
    JSONObject *json2 = NULL;
    const int localConfigTracing = false;

    json2 = my_parseJSON(szJsonConfig);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse JSON string\n");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localConfigTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s\r\n", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");



        if (strcmp(json2->pairs[ii].key,"AuthSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"AUTHTYPE")==0)
                    {
                        my_strlcpy(pIBRand->szAuthType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHURL")==0)
                    {
                        my_strlcpy(pIBRand->szAuthUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHUSER")==0)
                    {
                        my_strlcpy(pIBRand->szUsername, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szUsername));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHPSWD")==0)
                    {
                        my_strlcpy(pIBRand->szPassword, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szPassword));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHRETRYDELAY")==0)
                    {
                        pIBRand->authRetryDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"SecuritySettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"USESECURERNG")==0)
                    {
                        pIBRand->useSecureRng = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"OURKEMSECRETKEYFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->ourKemSecretKeyFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->ourKemSecretKeyFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"THEIRSIGNINGPUBLICKEYFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->theirSigningPublicKeyFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->theirSigningPublicKeyFilename));
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"CommsSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"BASEURL")==0)
                    {
                        my_strlcpy(pIBRand->szBaseUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szBaseUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"BYTESPERREQUEST")==0)
                    {
                        pIBRand->bytesPerRequest = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"RETRIEVALRETRYDELAY")==0)
                    {
                        pIBRand->retrievalRetryDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"StorageSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"STORAGETYPE")==0)
                    {
                        my_strlcpy(pIBRand->szStorageType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEDATAFORMAT")==0)
                    {
                        my_strlcpy(pIBRand->szStorageDataFormat, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageDataFormat));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->szStorageFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOCKFILEPATH")==0)
                    {
                        my_strlcpy(pIBRand->szStorageLockfilePath, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageLockfilePath));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEHIGHWATERMARK")==0)
                    {
                        pIBRand->storageHighWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOWWATERMARK")==0)
                    {
                        pIBRand->storageLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"IDLEDELAY")==0)
                    {
                        pIBRand->idleDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"GeneralSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"LOGGING_VERBOSITY")==0)
                    {
                        pIBRand->fVerbose = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}

static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    char *szJsonConfig;
    int rc;

    rc = my_readEntireConfigFileIntoMemory(szConfigFilename, &szJsonConfig);
    if (rc)
    {
        app_tracef("ERROR: Error %d reading JSON config from file: %s", rc, szConfigFilename);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    app_tracef("INFO: Configuration file (JSON format) [%s] (%u bytes)", szConfigFilename, strlen(szJsonConfig));

    rc = __ParseJsonConfig(szJsonConfig, pIBRand);
    if (!rc)
    {
        app_tracef("ERROR: Error %d parsing JSON config\n", rc);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    if (szJsonConfig) free(szJsonConfig);

    rc = validateSettings(pIBRand);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }

    rc = ReadContentsOfFile(pIBRand->ourKemSecretKeyFilename, &pIBRand->ourKemSecretKey, CRYPTO_SECRETKEYBYTES);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to read our secret key from file");
        return rc;
    }
    rc = ReadContentsOfFile(pIBRand->theirSigningPublicKeyFilename, &pIBRand->theirSigningPublicKey, CRYPTO_PUBLICKEYBYTES);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to read their public key from file");
        return rc;
    }

    return 0;
}
#endif // USE_CONFIG

static void PrintConfig(tIB_INSTANCEDATA *pIBRand)
{
    // Hide the password against wandering eyes
    char hiddenPassword[32];

    memset(hiddenPassword, 0, sizeof(hiddenPassword));
    for (int ii=0; ii<my_minimum(sizeof(hiddenPassword)-1,strlen(pIBRand->szPassword)); ii++)
       hiddenPassword[ii] = '*';

    app_tracef("szAuthType            =[%s]" , pIBRand->szAuthType            ); // char          szAuthType               [16]   // "SIMPLE";
    app_tracef("szAuthUrl             =[%s]" , pIBRand->szAuthUrl             ); // char          szAuthUrl                [128]  // "https://ironbridgeapi.com/login";
    app_tracef("szUsername            =[%s]" , pIBRand->szUsername            ); // char          szUsername               [32]   //
    app_tracef("szPassword            =[%s]" , hiddenPassword                 ); // char          szPassword               [32]   //
    app_tracef("authRetryDelay        =[%d]" , pIBRand->authRetryDelay        ); // int           authRetryDelay                  //
    //app_tracef("ourKemSecretKey       =[%s]" , hiddenKemSecretKey             );
    //app_tracef("theirSigningPublicKey =[%s]" , pIBRand->theirSigningPublicKey );
    app_tracef("useSecureRng          =[%u]" , pIBRand->useSecureRng          );
    app_tracef("szBaseUrl             =[%s]" , pIBRand->szBaseUrl             ); // char          szBaseUrl                [128]  // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    app_tracef("bytesPerRequest       =[%d]" , pIBRand->bytesPerRequest       ); // int           bytesPerRequest                 // 16
    app_tracef("retrievalRetryDelay   =[%d]" , pIBRand->retrievalRetryDelay   ); // int           retrievalRetryDelay             //
    app_tracef("szStorageType         =[%s]" , pIBRand->szStorageType         ); // char          szStorageType            [16]   // "FILE";
    app_tracef("szStorageDataFormat   =[%s]" , pIBRand->szStorageDataFormat   ); // char          szStorageDataFormat      [16]   // RAW, BASE64, HEX
    app_tracef("szStorageFilename     =[%s]" , pIBRand->szStorageFilename     ); // char          szStorageFilename        [128]  // "/var/lib/ibrand/ibrand_data.bin";
    app_tracef("szStorageLockfilePath =[%s]" , pIBRand->szStorageLockfilePath ); // char          szStorageLockfilePath    [128]  // "/tmp";
    app_tracef("storageHighWaterMark  =[%ld]", pIBRand->storageHighWaterMark  ); // long          storageHighWaterMark            // 1038336; // 1MB
    app_tracef("storageLowWaterMark   =[%ld]", pIBRand->storageLowWaterMark   ); // long          storageLowWaterMark             // 102400; // 100KB
    app_tracef("idleDelay             =[%d]" , pIBRand->idleDelay             ); // int           idleDelay                       //
    app_tracef("fVerbose              =[%u]" , pIBRand->fVerbose              ); // unsigned char fVerbose                        // bit 0=general, bit1=auth, bit2=data, bit3=curl:
}

int main(int argc, char * argv[])
{
    // Our process ID and Session ID
#ifdef RUN_AS_DAEMON
    pid_t processId = {0};
    pid_t sessionId = {0};
#endif // RUN_AS_DAEMON
    int rc;
    tIB_INSTANCEDATA *pIBRand;


    // =========================================================================
    // Create instance storage
    // =========================================================================
    pIBRand = malloc(sizeof(tIB_INSTANCEDATA));
    if (!pIBRand)
    {
        fprintf(stderr, "FATAL: Failed to allocate memory for local storage. Aborting.");
        exit(EXIT_FAILURE);
    }
    memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));

    // =========================================================================
    // And they're off!!!
    // =========================================================================
    fprintf(stdout, "IronBridge(tm) IBRand Service v0.40\n");
    fprintf(stdout, "Copyright (c) 2020 Cambridge Quantum Computing Limited. All rights reserved.\n");
    fprintf(stdout, "\n");

    if ((argc > 2) && strcmp(argv[1],"-f")==0)
    {
        my_strlcpy(pIBRand->szConfigFilename, argv[2], sizeof(pIBRand->szConfigFilename));
    }
    else
    {
        char *tempPtr;
        rc = my_getFilenameFromEnvVar("IBRAND_CONF", &tempPtr);
        if (rc==0)
        {
            my_strlcpy(pIBRand->szConfigFilename, tempPtr, sizeof(pIBRand->szConfigFilename));
            free(tempPtr);
        }
    }

    if (strlen(pIBRand->szConfigFilename) == 0)
    {
        fprintf(stderr, "FATAL: Configuration not specified, neither on commandline nor via an environment variable.\n");
        fprintf(stderr, "USAGE: ibrand_service [-f <ConfigFilename>]\n");
        fprintf(stderr, "       If <ConfigFilename> is NOT specified on the command line,\n");
        fprintf(stderr, "       then it must be specified in envar \"IBRAND_CONF\".\n");
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef RUN_AS_DAEMON
    app_trace_openlog("ibrand_service", LOG_PID, LOG_DAEMON);
#else // RUN_AS_DAEMON
    app_trace_openlog("ibrand_service", LOG_PID|LOG_CONS|LOG_PERROR, LOG_USER );
#endif // RUN_AS_DAEMON

    rc = ReadConfig(pIBRand->szConfigFilename, pIBRand);
    if (rc != 0)
    {
        fprintf(stderr, "FATAL: Configuration error. rc=%d\n", rc);
        app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef RUN_AS_DAEMON
    // Fork off the parent process
    processId = fork();
    if (processId < 0)
    {
        fprintf(stderr, "FATAL: Failed to create child process\n");
        app_tracef("FATAL: Failed to create child process. Aborting.");
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }
    // If we got a good pid, then we can exit the parent process.
    if (processId > 0)
    {
        /////////////////////////////////////////
        // We are the parent process
        /////////////////////////////////////////
        fprintf(stdout, "INFO: IBRand Service started successfully (pid:%u)\n", processId);
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
            app_tracef("INFO: IBRand Service started successfully (pid:%u)", processId);
        app_trace_closelog();
        exit(EXIT_SUCCESS);
    }

    /////////////////////////////////////////
    // We are the child process
    /////////////////////////////////////////

    processId = getpid(); // was, by definition, 0
    app_tracef("INFO: CQC IronBridge IBRand Service Started Successfully (pid:%u)====================", processId);

    // Change the file mode mask
    umask(0);

    // Open any logs here

    // Create a new SID for the child process
    sessionId = setsid();
    if (sessionId < 0)
    {
        app_tracef("FATAL: Failed to create a new SID for the child process. Aborting.");
        // Log the failure
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

    // Change the current working directory
    if ((chdir("/")) < 0)
    {
        // Log the failure
        app_tracef("FATAL: Chdir failed. Aborting");
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef FORCE_ALL_LOGGING_ON
    SET_BIT(pIBRand->fVerbose, DBGBIT_STATUS );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CONFIG );
    SET_BIT(pIBRand->fVerbose, DBGBIT_AUTH   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_DATA   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CURL   );
    // Leave the standard file descriptors open
#else // FORCE_ALL_LOGGING_ON
    // Close out the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif // FORCE_ALL_LOGGING_ON

#else // RUN_AS_DAEMON
    app_tracef("INFO: CQC IronBridge IBRand Process Started Successfully ====================");
#endif // RUN_AS_DAEMON

    // =========================================================================
    // Daemon-specific initialization
    // =========================================================================

    // =========================================================================
    // Main loop
    // =========================================================================

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CONFIG))
    {
        PrintConfig(pIBRand);
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: Running");

    unsigned long numberOfAuthSuccesses =  0;
    unsigned long numberOfAuthFailures =  0;
    unsigned long numberOfConsecutiveAuthFailures =  0;

    unsigned long numberOfRetreivalSuccesses =  0;
    unsigned long numberOfRetreivalFailures =  0;
    unsigned long numberOfConsecutiveRetreivalFailures =  0;

    pIBRand->ResultantData.pData = NULL;
    pIBRand->ResultantData.cbData = 0;

    int GetSomeData = true;
    long filesize = 0;

    // Ensure that we don't still have a lock file from a previous run
    my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);

    // The Big Loop
    while (1)
    {
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        {
            app_tracef("INFO: Stats("
                              "AUTH(S%lu,F%lu,f%lu),"
                              "RNG(S%lu,F%lu,f%lu),"
                              "DATA(A%d,N%ld))",
                             numberOfAuthSuccesses, numberOfAuthFailures, numberOfConsecutiveAuthFailures,
                             numberOfRetreivalSuccesses, numberOfRetreivalFailures, numberOfConsecutiveRetreivalFailures,
                             GetSomeData, filesize);
        }
        if (!pIBRand->fCurlInitialised)
        {
            rc = InitialiseCurl(pIBRand);
            if (rc != 0)
            {
#ifdef RUN_AS_DAEMON
                app_tracef("ERROR: InitialiseCurl failed with rc=%d. Will retry initialisation in %d seconds", rc, pIBRand->authRetryDelay);
                sleep(pIBRand->authRetryDelay);
                continue;
#else // RUN_AS_DAEMON
                app_tracef("ERROR: InitialiseCurl failed with rc=%d. Aborting.", rc);
                break;
#endif // RUN_AS_DAEMON
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
                app_tracef("INFO: Curl Initialisation OK");
        }

        if (!pIBRand->fAuthenticated)
        {
            rc = DoAuthentication(pIBRand);
            if (rc != 0)
            {
                numberOfAuthFailures++;
                numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                app_tracef("ERROR: DoAuthentication failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                sleep(pIBRand->authRetryDelay);
                continue;
#else // RUN_AS_DAEMON
                app_tracef("ERROR: DoAuthentication failed with rc=%d. Aborting.", rc);
                break;
#endif // RUN_AS_DAEMON
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                app_tracef("INFO: Authentication OK");
            numberOfAuthSuccesses++;
            numberOfConsecutiveAuthFailures = 0;
        }

        // Get SessionKey (aka SharedSecret)
        if (pIBRand->symmetricSessionKey.pData == NULL)
        {
            // Do we already have an encapsulatedSessionKey ?
            if (pIBRand->encapsulatedSessionKey.pData == NULL)
            {
                rc = getSecureRNGSessionKey(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: DoRequestSessionKey failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    continue;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: DoRequestSessionKey failed with rc=%d. Aborting.", rc);
                    break;
#endif // RUN_AS_DAEMON
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Encapsulated Session Key OK");
                // Loop around and try again
                continue;
            }
            else
            {
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Decapsulating session key");
                int rc = DecapsulateAndStoreSessionKey(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    continue;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Aborting.", rc);
                    break;
#endif // RUN_AS_DAEMON
                }
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                app_tracef("INFO: Session key OK");
            numberOfAuthSuccesses++;
            numberOfConsecutiveAuthFailures = 0;
        }

        // Hysteresis
        filesize = my_getFilesize(pIBRand->szStorageFilename);
        //app_tracef("DEBUG: Filename=\"%s\", Filesize=%d", pIBRand->szStorageFilename, filesize);
        if (filesize < 0) // File not found
        {
            app_tracef("INFO: File non-existant. Starting retrieval.", pIBRand->retrievalRetryDelay);
            GetSomeData = true;
        }
        else
        {
            if (GetSomeData == true) // We are busy filling up the cache
            {
                if (filesize >= pIBRand->storageHighWaterMark) // is it full yet?
                {
                    app_tracef("INFO: High water mark reached. Pausing retrieval.", pIBRand->retrievalRetryDelay);
                    GetSomeData = false;
                }
            }
            else // We are sitting idle because there is enough data in the cache
            {
                if (filesize <= pIBRand->storageLowWaterMark) // Is it nearly empty
                {
                    app_tracef("INFO: Low water mark reached. Starting retrieval.", pIBRand->retrievalRetryDelay);
                    GetSomeData = true;
                }
            }
        }

        if (GetSomeData)
        {
            //////////////////////////////
            // Get the RNG material
            //////////////////////////////
            rc = getRandomBytes(pIBRand);
            if (rc != 0)
            {
                numberOfRetreivalFailures++;
                numberOfConsecutiveRetreivalFailures++;
                app_tracef("ERROR: %s Failed with rc=%d. Will try again in %d seconds", pIBRand->useSecureRng?"SRNG":"RNG", rc, pIBRand->retrievalRetryDelay);
                sleep(pIBRand->retrievalRetryDelay);
            }
            else if (pIBRand->ResultantData.pData == NULL || pIBRand->ResultantData.cbData == 0 )
            {
                numberOfRetreivalFailures++;
                numberOfConsecutiveRetreivalFailures++;
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
                    app_tracef("WARNING: %s No data received. Will try again in %d seconds", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->retrievalRetryDelay);
                sleep(pIBRand->retrievalRetryDelay);
            }
            else
            {
                numberOfRetreivalSuccesses++;
                numberOfConsecutiveRetreivalFailures = 0;
                // pIBRand->ResultantData.pData must be freed by the caller
                storeRandomBytes(pIBRand);
            }
            if (pIBRand->ResultantData.pData)
            {
                free(pIBRand->ResultantData.pData);
                pIBRand->ResultantData.pData = NULL;
            }
            pIBRand->ResultantData.cbData = 0;
        }
        else
        {
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
                app_tracef("INFO: Idle. Sleeping for %d seconds", pIBRand->idleDelay);
            sleep(pIBRand->idleDelay);
        }
    }

    ironbridge_api_finalise(pIBRand);

    app_tracef("WARNING: Terminating Service");
    app_trace_closelog();
    exit(EXIT_SUCCESS);
}
