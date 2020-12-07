///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// Based loosely on the service template provided by Devin Watson:
// http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html
//
///////////////////////////////////////////////////////////////////////////////

#define _GNU_SOURCE // Needed for setenv() and unsetenv() which are platform specific and hence not in all standards

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

#include "ibrand_service_kem.h"
#include "../ibrand_common/my_utilslib.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_config.h"

#include "ibrand_service_comms.h"

#if LIBCURL_VERSION_NUM < 0x070c03
#error "ERROR - Requires libcurl of 7.12.3 or greater"
#endif

// It seems that openssl is running on a different copy
// of the environment, because this removal of OPENSSL_CONF
// envvar makes no differemce.
// Leaving it here in case it proves useful later, or at
// very least for debugging.
//#define DISABLE_IBRAND_BY_REMOVING_ENVVAR

//#define HTTP_RESP_KEMKEYPAIREXPIRED    (426) // Upgrade Required
//#define HTTP_RESP_SHAREDSECRETEXPIRED  (424) // Failed Dependency (WebDAV)
//#define HTTP_RESP_PRECONDITIONFAILED   (412) // PreconditionFailed 412
#define HTTP_RESP_TOKENEXPIREDORINVALID  (498) // TokenExpiredOrInvalid 498
#define HTTP_RESP_KEMKEYPAIREXPIRED      (499) // TokenExpiredOrInvalid 498
#define HTTP_RESP_SHAREDSECRETEXPIRED    (498) // TokenExpiredOrInvalid 498


//-----------------------------------------------------------------------
// PrintOpenSSLEngines
//-----------------------------------------------------------------------
static void PrintOpenSSLEngines(CURL *hCurl, char *szTitle)
{
    struct curl_slist *engines = NULL;
    struct curl_slist *e;
    CURLcode curlResultCode;
    int n;

    curlResultCode = curl_easy_getinfo(hCurl, CURLINFO_SSL_ENGINES, &engines);
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("WARNING: OpenSSL engine query failed: ResultCode=%03ld \"%s\"", curlResultCode, curl_easy_strerror(curlResultCode));
        return;
    }
    if (engines == NULL)
    {
        app_tracef("WARNING: No OpenSSL engines found");
        return;
    }

    // Count the number of engines in the list
    for (e=engines, n=0; e != NULL; e = e->next, n++);

    app_tracef("INFO: OpenSSL Engines found at %s: %d", szTitle, n);
    // Print out the name of each engine in the list
    for (e=engines, n=0; e != NULL; e = e->next, n++)
    {
        app_tracef("INFO:   OpenSSL Engine[%d]: \"%s\"", n, e->data);
    }

    // Free up the linked-list
    curl_slist_free_all(engines);
}

#ifdef DISABLE_IBRAND_BY_REMOVING_ENVVAR
//-----------------------------------------------------------------------
// PrintEnvVar
//-----------------------------------------------------------------------
static void PrintEnvVar(char *szTitle, char *szEnvVar)
{
    char *pValue = getenv(szEnvVar);
    app_tracef("INFO: %s, EnvVar %s=\"%s\"", szTitle, szEnvVar, pValue?pValue:"<NULL>");
}
#endif // DISABLE_IBRAND_BY_REMOVING_ENVVAR

static bool IsOpensslRngEngineActive(CURL *hCurl, char *szWhichEngine)
{
    struct curl_slist *engines = NULL;
    struct curl_slist *e;
    CURLcode curlResultCode;
    int n;

    curlResultCode = curl_easy_getinfo(hCurl, CURLINFO_SSL_ENGINES, &engines);
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("WARNING: OpenSSL engine query failed: ResultCode=%03ld \"%s\"", curlResultCode, curl_easy_strerror(curlResultCode));
        return false;
    }
    if (engines == NULL)
    {
        app_tracef("WARNING: No OpenSSL engines found");
        return false;
    }

    // Print out the name of each engine in the list
    for (e=engines, n=0; e != NULL; e = e->next, n++)
    {
        if (strcmp(e->data, szWhichEngine) == 0)
        {
            curl_slist_free_all(engines);
            return true;
        }
    }

    // Free up the linked-list
    curl_slist_free_all(engines);
    return false;
}

static bool SetOpensslRngEngine(tIB_INSTANCEDATA *pIBRand, char *szWhichEngine)
{
    // Typical values for szWhichEngine are: NULL, "rdrand", "dynamic", "md_rand", and ofcourse ours... "ibrand".
    // This fn will force use of non-IronBridge OpenSSL RNG engine
    // Anything except ourselves (ibrand).

    CURLcode ret;

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL)) // We'll use DBGBIT_CURL for stuff that is called often, and DBGBIT_CONFIG for startup one-offs.
    {
        app_tracef("INFO: Set preferred OpenSSL RNG engine: %s", szWhichEngine?szWhichEngine:"NULL");
    }

    // https://wiki.openssl.org/index.php/Random_Numbers#Generators says...
    // By default, OpenSSL uses the md_rand generator. md_rand uses the MD5 hash as the pseudorandom function.
    // The source code is located in crypto/rand/md_rand.c.

    ret = curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, szWhichEngine);
    if (ret != CURLE_OK)
    {
        // e.g. CURLE_SSL_ENGINE_INITFAILED (66) : Initiating the SSL Engine failed.
        //      CURLE_SSL_ENGINE_NOTFOUND   (53) : The specified crypto engine wasn't found.
        app_tracef("ERROR: CURLOPT_SSLENGINE (%s) failed with ret=%d", szWhichEngine?szWhichEngine:"NULL",ret);
        return false;
    }
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
    {
        app_tracef("INFO: CURLOPT_SSLENGINE_DEFAULT");
    }
    ret = curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE_DEFAULT, 1L);
    if (ret != CURLE_OK)
    {
        // e.g. CURLE_SSL_ENGINE_SETFAILED  (54) : Failed setting the selected SSL crypto engine as default!
        app_tracef("ERROR: CURLOPT_SSLENGINE_DEFAULT (%s) failed with ret=%d", szWhichEngine?szWhichEngine:"NULL",ret);
        return false;
    }
    return true;
}

static tERRORCODE SetupRNGForSSLConnection(tIB_INSTANCEDATA *pIBRand, bool isBeforeConnection, int *pActionTaken)
{
    tERRORCODE erc = ERC_UNSPECIFIED_ERROR;
#ifdef DISABLE_IBRAND_BY_REMOVING_ENVVAR
    static char saveOpensslEnvVar[_MAX_PATH];
#endif
    enum eACTIONTAKEN
    {
        ACT_NO_ACTION_TAKEN = 0,
        ACT_USING_DEFAULT_RNG,
        ACT_USING_STDRAND_RNG,
        ACT_USING_RDRAND_RNG,
#ifdef DISABLE_IBRAND_BY_REMOVING_ENVVAR
        ACT_IBRAND_ENVVAR_REMOVED,
#endif
        ACT_PRAY_AND_HOPE_FOR_THE_BEST,
        ACT_ENDMARKER
    };
    char *szActionTakenName[] =
    {
        "ACT_NO_ACTION_TAKEN",
        "ACT_USING_DEFAULT_RNG",
        "ACT_USING_STDRAND_RNG",
        "ACT_USING_RDRAND_RNG",
#ifdef DISABLE_IBRAND_BY_REMOVING_ENVVAR
        "ACT_IBRAND_ENVVAR_REMOVED",
#endif
        "ACT_PRAY_AND_HOPE_FOR_THE_BEST",
        "ACT_ENDMARKER"
    };

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL)) // We'll use DBGBIT_CURL for stuff that is called often, and DBGBIT_CONFIG for startup one-offs.
    {
        if (!isBeforeConnection)
        {
            app_tracef("INFO: (exit) OpenSSL ActionTake=%d:%s", *pActionTaken,szActionTakenName[*pActionTaken]);
        }
        PrintOpenSSLEngines(pIBRand->hCurl, "entry");
    }
    if (isBeforeConnection)
    {
        *pActionTaken = ACT_NO_ACTION_TAKEN;
        if (IsOpensslRngEngineActive(pIBRand->hCurl, "ibrand") == false)
        {
            *pActionTaken = ACT_USING_DEFAULT_RNG;
            erc = ERC_OK;
            goto CLEANUP_AND_EXIT;
        }
        if (IsOpensslRngEngineActive(pIBRand->hCurl, "stdrand") == true)
        {
            if (SetOpensslRngEngine(pIBRand, "stdrand"))
            {
                *pActionTaken = ACT_USING_STDRAND_RNG;
                erc = ERC_OK;
                goto CLEANUP_AND_EXIT;
            }
            // else, fall through
        }
        if (IsOpensslRngEngineActive(pIBRand->hCurl, "rdrand") == true)
        {
            if (SetOpensslRngEngine(pIBRand, "rdrand"))
            {
                *pActionTaken = ACT_USING_RDRAND_RNG;
                erc = ERC_OK;
                goto CLEANUP_AND_EXIT;
            }
            // else, fall through
        }
#ifdef DISABLE_IBRAND_BY_REMOVING_ENVVAR
        char *pOpenSSLEnvVar = getenv ("OPENSSL_CONF");
        if (pOpenSSLEnvVar == NULL)
        {
            *pActionTaken = ACT_PRAY_AND_HOPE_FOR_THE_BEST;
            erc = ERC_OK;
            goto CLEANUP_AND_EXIT;
        }
        my_strlcpy(saveOpensslEnvVar, pOpenSSLEnvVar, sizeof(saveOpensslEnvVar)-1);

        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
            PrintEnvVar("(BeforeConnection, BeforeUnsetenv)", "OPENSSL_CONF");
        int ret = unsetenv("OPENSSL_CONF");
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
            PrintEnvVar("(BeforeConnection, AfterUnsetenv)", "OPENSSL_CONF");
        if (ret == 0)
        {
            *pActionTaken = ACT_IBRAND_ENVVAR_REMOVED;
            erc = ERC_OK;
            goto CLEANUP_AND_EXIT;
        }
        // Failed to remove envvar
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
            PrintEnvVar("(BeforeConnection, BeforeSetenv(dummy))", "OPENSSL_CONF");
        ret = setenv("OPENSSL_CONF", "dummy", true);
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
            PrintEnvVar("(BeforeConnection, AfterSetenv(dummy))", "OPENSSL_CONF");
        if (ret == 0)
        {
            *pActionTaken = ACT_IBRAND_ENVVAR_REMOVED;
            erc = ERC_OK;
            goto CLEANUP_AND_EXIT;
        }
#endif // DISABLE_IBRAND_BY_REMOVING_ENVVAR
        *pActionTaken = ACT_PRAY_AND_HOPE_FOR_THE_BEST;
        erc = ERC_OK;
    }
    else // exit
    {
        switch (*pActionTaken)
        {
            case ACT_USING_DEFAULT_RNG:
            case ACT_PRAY_AND_HOPE_FOR_THE_BEST:
            default:
                // Nothing to undo
                erc = ERC_OK;
                break;
            case ACT_USING_RDRAND_RNG:
                // Nothing to undo
                erc = ERC_OK;
                break;
#ifdef DISABLE_IBRAND_BY_REMOVING_ENVVAR
            case ACT_IBRAND_ENVVAR_REMOVED:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
                    PrintEnvVar("(AfterConnection, BeforeSetenv(savedvalue))", "OPENSSL_CONF");
                int ret = setenv("OPENSSL_CONF", saveOpensslEnvVar, true);
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
                    PrintEnvVar("(AfterConnection, AfterSetenv(savedvalue))", "OPENSSL_CONF");
                if (ret != 0)
                {
                    // There is not much we can do about this...
                    erc = ERC_IBCOM_SET_ENVVAR_FAILED;
                    break;
                }
                break;
            }
#endif // DISABLE_IBRAND_BY_REMOVING_ENVVAR
        }
        *pActionTaken = ACT_NO_ACTION_TAKEN;
    }
CLEANUP_AND_EXIT:
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
    {
        if (isBeforeConnection)
        {
            app_tracef("INFO: (entry) OpenSSL ActionTake=%d:%s", *pActionTaken,szActionTakenName[*pActionTaken]);
        }
        PrintOpenSSLEngines(pIBRand->hCurl, "exit");
    }
    return erc;
}

//-----------------------------------------------------------------------
// CommsInitialise
//-----------------------------------------------------------------------
tERRORCODE CommsInitialise(tIB_INSTANCEDATA *pIBRand)
{
    //////////////////////////////
    // Initialise libcurl
    //////////////////////////////
    // In windows, this will init the winsock stuff
    curl_global_init(CURL_GLOBAL_ALL);

    pIBRand->hCurl = curl_easy_init();
    if (!pIBRand->hCurl)
    {
      app_tracef("ERROR: Library initialisation failed");
      return ERC_IBCOM_CURL_INITIALISATION_FAILED;
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
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
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG)) // We'll use DBGBIT_CURL for stuff that is called often, and DBGBIT_CONFIG for startup one-offs.
    {
        PrintOpenSSLEngines(pIBRand->hCurl, "Init");
    }

    pIBRand->fCurlInitialised = TRUE;
    return ERC_OK;
}

void CommsFinalise(tIB_INSTANCEDATA *pIBRand)
{
    curl_easy_cleanup(pIBRand->hCurl);
    curl_global_cleanup();
}

tERRORCODE callToRemote(tIB_INSTANCEDATA *pIBRand,
                        const char * pUrl,
                        const char *szEndpoint,
                        bool isAuthenticationCall,
                        size_t (* callbackFunction)(char *buffer, size_t size, size_t nmemb, void *userp),
                        int *pCountRcvdSegments,
                        tLSTRING *pResult,
                        const char *szResultDescription)
{
    struct curl_slist *headers = NULL;
    CURLcode curlResultCode;
    long httpConnectionCode = 0;
    long httpResponseCode = 0;
    char *pAuthHeader = NULL;
    char bodyData[1024] = "";

    if (!pIBRand)
    {
        app_tracef("ERROR: Parameter error - instance data is null");
        return ERC_IBCOM_PARAMETER_ERROR_INSTANCE_DATA_IS_NULL;
    }

    if(!isAuthenticationCall)
    {
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    // Pass our list of custom made headers
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    if (isAuthenticationCall)
    {
        headers = curl_slist_append ( headers, "Authorization: Bearer" );
    }
    else
    {
        headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
        if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
        {
            // e.g.
            //   "name": "accept",
            //   "value": "application/json, text/plain, */*"
            //   "name": "authorization",
            //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
            //   "name": "content-type",
            //   "value": "application/json"

            pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
            if (!pAuthHeader)
            {
                app_tracef("ERROR: Out of memory allocating for AuthHeader");
                curl_slist_free_all(headers); // Free custom header list
                return ERC_IBCOM_NOMEM_FOR_AUTH_HEADER;
            }
            sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);
            if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            {
                app_tracef("INFO: %s AuthHeader = \"%s\"", szEndpoint, pAuthHeader);
            }
            headers = curl_slist_append ( headers, pAuthHeader );
        }
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);

    if (isAuthenticationCall)
    {
        sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", pIBRand->cfg.szUsername, pIBRand->cfg.szPassword );
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_POSTFIELDS, bodyData);
    }

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, callbackFunction);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    // Prepare the pIBRand for the new shared secret/pem key/rng data/etc
    if (pCountRcvdSegments)
    {
       *pCountRcvdSegments = 0;
    }

    if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
        // Client Certificate
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->cfg.szAuthSSLCertFile, pIBRand->cfg.szAuthSSLCertType);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->cfg.szAuthSSLCertFile);
            //curl_slist_free_all(headers); // Free custom header list
            //if (pAuthHeader) free(pAuthHeader);
            //return ERC_IBCOM_NOENT_CLIENT_CERT_FILE_NOT_FOUND;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->cfg.szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->cfg.szAuthSSLCertType); // Load the certificate type

        // SSL Key
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using Client SSL key \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLKeyFile))
        {
            app_tracef("WARNING: Client SSL key file not found: \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
            //curl_slist_free_all(headers); // Free custom header list
            //if (pAuthHeader) free(pAuthHeader);
            //return ERC_IBCOM_NOENT_CLIENT_KEY_FILE_NOT_FOUND;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY     , pIBRand->cfg.szAuthSSLKeyFile ); // Load the key
    }

    // if (!SetOpensslRngEngine(pIBRand))
    // {
    //     app_tracef("ERROR: Failed to set preferred openssl RNG engine for SSL connection");
    //     curl_slist_free_all(headers); // Free custom header list
    //     if (pAuthHeader) free(pAuthHeader);
    //     return ERC_IBCOM_OPENSSL_PREFERRED_ENGINE_NOT_SET;
    // }

    // if ibrand engine is active, then use stdrand or rdrand engine
    // If neither are available, then remove environment variable in an and try that.
    int rngActionTaken = 0;
    SetupRNGForSSLConnection(pIBRand, true, &rngActionTaken);

    if (isAuthenticationCall)
    {
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
        {
            app_tracef("INFO: Connecting to \"%s\" with \"%s\"", pUrl, bodyData);
        }
    }

    // Do it
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s Sending \"%s\"", szEndpoint, pUrl );
    }

    // Step 1 - Do the post
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s response code = %ld", szEndpoint, httpResponseCode);
    }

    // Restore enironment variable (if that is what was done)
    SetupRNGForSSLConnection(pIBRand, false, &rngActionTaken);

    if (curlResultCode != CURLE_OK)
    {
        if (isAuthenticationCall)
        {
            app_tracef("ERROR: authenticateUser failed: rc=%d \"%s\"", curlResultCode, curl_easy_strerror(curlResultCode));
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            return ERC_IBCOM_AUTH_USER_FAILED;
        }
        else
        {
            if (httpResponseCode == HTTP_RESP_SHAREDSECRETEXPIRED)
            {
                curl_slist_free_all(headers); // Free custom header list
                if (pAuthHeader) free(pAuthHeader);
                return ERC_IBCOM_SHAREDSECRET_EXPIRED;
            }
            else if (httpResponseCode == HTTP_RESP_KEMKEYPAIREXPIRED)
            {
                curl_slist_free_all(headers); // Free custom header list
                if (pAuthHeader) free(pAuthHeader);
                return ERC_IBCOM_KEMKEYPAIR_EXPIRED;
            }
            else
            {
                app_tracef("ERROR: %s perform failed: curl:%ld [%s] http:%ld [%s]", szEndpoint, curlResultCode, curl_easy_strerror(curlResultCode), httpResponseCode, HttpResponseCodeDescription(httpResponseCode));
                if (pResult->pData && pResult->cbData)
                {
                    app_tracef("ERROR: %s response: [%s]", szEndpoint, pResult->pData);
                }
                curl_slist_free_all(headers); // Free custom header list
                if (pAuthHeader) free(pAuthHeader);
                return ERC_IBCOM_CURL_PERFORM_FAILED;
            }
        }
    }

    if (isAuthenticationCall)
    {
        // Step 2 - Get HTTP Connect Code
        curlResultCode = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_HTTP_CONNECTCODE, &httpConnectionCode);
        if (!curlResultCode && httpConnectionCode)
        {
            app_tracef("ERROR: authenticateUser: httpConnectionCode=%03ld", httpConnectionCode);
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            return ERC_IBCOM_HTTP_CONNECTION_ERROR;
        }

        if (httpResponseCode != 200)
        {
            app_tracef("ERROR: authenticateUser: HTTP Responcse Code=%ld", httpResponseCode);
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            return ERC_IBCOM_AUTH_USER_FAILED_WITH_RESPONSECODE;
        }

        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
        {
            if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
            {
                app_tracef("INFO: authenticateUser() authToken = [%s]"            , pIBRand->authToken.pData);
            }
        }

        app_tracef("INFO: Authentication successful: (\"%s\", \"%s\")", pUrl, pIBRand->cfg.szUsername);
    }
    else
    {
        UNUSED_PARAM(szResultDescription);
        //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        //{
        //    app_tracef("INFO: %s %s = [%*.*s]", szEndpoint, szResultDescription, pResult->cbData, pResult->cbData, pResult->pData);
        //}
    }

    curl_slist_free_all(headers); // Free custom header list
    if (pAuthHeader) free(pAuthHeader);
    return ERC_OK;
}
