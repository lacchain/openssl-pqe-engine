
//-----------------------------------------------------------------------
// File: ibrand_service.c
// Copyright (c) 2019 Cambridge Quantum Computing Limited. All rights reserved.
//-----------------------------------------------------------------------

// Based on the service template provided by Devin Watson:
// http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include "my_utilslib.h"


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

#ifdef FORCE_ALL_LOGGING_ON
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
    char          szAuthType[16];                   // "SIMPLE";
    char          szAuthUrl[128];                   // "https://ironbridgeapi.com/login";
    char          szUsername[32];
    char          szPassword[32];
    int           authRetryDelay;

    char          szBaseUrl[128];                   // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    int           bytesPerRequest;                  // Tested with 16 & 256
    int           retrievalRetryDelay;

    char          szStorageType[16];                // "FILE";
    char          szStorageDataFormat[16];          // RAW, BASE64, HEX
    char          szStorageFilename[_MAX_PATH];     // "/var/lib/ibrand/ibrand_data.bin";
    char          szStorageLockfilePath[_MAX_PATH]; // "/tmp";
    long          storageHighWaterMark;             // 1038336; // 1MB
    long          storageLowWaterMark;              // 102400; // 100KB
    int           idleDelay;

    unsigned char  fVerbose;                        // bit 0=general, bit1=config bit2=auth, bit3=data, bit4=curl:

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
} tIB_INSTANCEDATA;

//-----------------------------------------------------------------------
// AppendNewDataToLstring
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->Token)
//-----------------------------------------------------------------------
size_t AppendNewDataToLstring(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pNewData;
    size_t     cbNewData;
    tLSTRING * pLString;
    char *     pAllData;
    char *     pExistingData;
    size_t     cbExistingData;

    pNewData  = buffer;
    cbNewData = (size * nmemb);

    // Cast our userp back to its original (tLSTRING *) type
    pLString = (tLSTRING *)userp;
    if (!pLString)
    {
        app_tracef("ERROR: AppendNewDataToLstring() UserData is NULL");
        return 0;
    }

    pExistingData  = pLString->pData;
    cbExistingData = pLString->cbData;
    // If pLString already contains some data (i.e. cbExistingData > 0)
    // then we'll...
    //    a) alloc enough room for both
    //    b) copy in the existing data
    //    c) append our new data to it.

    // Allocate a new buffer
    pAllData = (char *)malloc(cbExistingData + cbNewData);
    if (pAllData == NULL)
    {
        app_tracef("ERROR: AppendNewDataToLstring() malloc failure");
        return 0;
    }

    // Copy in the existing data, if there is
    if (cbExistingData && pExistingData)
    {
        memcpy(pAllData, pExistingData, cbExistingData);
    }
    // Copy in the new data
    memcpy(pAllData+cbExistingData, pNewData, cbNewData);

    // Point our userp at the new buffer
    pLString->pData = pAllData;
    pLString->cbData = cbExistingData + cbNewData;

    // Free up the old buffer
    if (cbExistingData && pExistingData)
    {
        free(pExistingData);
        pExistingData = NULL;
        cbExistingData = 0;
    }

    //app_tracef("INFO: AppendNewDataToLstring() Saved %lu bytes", pLString->cbData);

    // Job done
    return cbNewData;
}

//-----------------------------------------------------------------------
// authenticateUser
//-----------------------------------------------------------------------
int authenticateUser(tIB_INSTANCEDATA *pIBRand)
{
    //app_tracef("{1}");
    if (!pIBRand)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - instance data is null");
        return 2200;
    }

    if (strlen(pIBRand->szAuthUrl) == 0)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - AuthUrl is empty");
        return 2201;
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
    sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", pIBRand->szUsername, pIBRand->szPassword );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_POSTFIELDS, bodyData);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, AppendNewDataToLstring);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, &pIBRand->Token);

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
      return 2202;
    }

    //app_tracef("{4}");
    pIBRand->code = 999;
    CURLcode curlResultCodeB;
    curlResultCodeB = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_HTTP_CONNECTCODE, &pIBRand->code);
    if (!curlResultCodeB && pIBRand->code)
    {
        app_tracef("ERROR: authenticateUser: ResultCode=%03ld (%s)", pIBRand->code, curl_easy_strerror(pIBRand->code));
        return 2203;
    }

    pIBRand->response_code = 999;
    CURLcode  curlResultCodeC;
    curlResultCodeC = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &pIBRand->response_code);
    if (!curlResultCodeC && (pIBRand->response_code != 200))
    {
        //app_tracef("{5e}");
        app_tracef("ERROR: authenticateUser: HTTP Responcse Code=%ld", pIBRand->response_code);
        return 2204;
    }

    //app_tracef("{6}");
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

    pUrl = (char *)malloc(strlen(pIBRand->szBaseUrl)+5+18); // i.e. strlen("/rng/") + strlen(itoa(numberOfBytes))
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2601;
    }
    sprintf(pUrl,"%s/rng/%u", pIBRand->szBaseUrl, pIBRand->bytesPerRequest);

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
        return 2602;
    }
    sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: RNG AuthHeader = \"%s\"", pAuthHeader);
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

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, AppendNewDataToLstring);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, &pIBRand->ResultantData);

    /* Do it */
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: RNG perform failed: [%s]", curl_easy_strerror(curlResultCode));
        return 2603;
    }

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: RNG ResultantData = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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
        return;
    }

    // Format the output data
    if (strcmp(pIBRand->szStorageDataFormat,"RAW")==0)
    {
        // Curl_base64_decode() - Given a base64 string at src, decode it and return
        // an allocated memory in the *outptr. Returns the length of the decoded data.
        //*pcbData = Curl_base64_decode(p, (unsigned char **)ppData)
        // *ppData will, and must, be freed by the caller

        //app_tracef("INFO: RNG ResultantData[%u] = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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

        pIBRand->ResultantData.pData = (char *)base64_decode(pDecodeData, cbDecodeData, (size_t *)&(pIBRand->ResultantData.cbData));
        if (!pIBRand->ResultantData.pData)
        {
           app_tracef("WARNING: Failed to decode Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
           return;
        }
        free(pOriginalData);
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: RNG ResultantData[%u]", pIBRand->ResultantData.cbData);
            //app_tracef("INFO: RNG ResultantData[%u] = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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
            app_tracef("INFO: RNG ResultantData = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
        }
    }
    else if (strcmp(pIBRand->szStorageDataFormat,"HEX")==0)
    {
        // TODO
    }

    if (strcmp(pIBRand->szStorageType,"FILE")==0)
    {
        //fprintf(stdout, "%u:%s\n", pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
        FILE *f;
        unsigned int bytesWritten;

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
        bytesWritten = fwrite(pIBRand->ResultantData.pData, 1, pIBRand->ResultantData.cbData, f);
        if (bytesWritten != pIBRand->ResultantData.cbData)
        {
            app_tracef("WARNING: Unable to write all bytes (%d/%d)", bytesWritten, pIBRand->ResultantData.cbData);
        }
        // Delimit each Base64 block with a LF
        if (strcmp(pIBRand->szStorageDataFormat,"BASE64")==0)
        {
            bytesWritten = fwrite("\n", 1, 1, f);
            if (bytesWritten != 1)
            {
                app_tracef("WARNING: Unable to write LF");
            }
        }
        fclose(f);
        my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
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
        app_tracef("ERROR: ExtractSubstring() Cannot find token in \"%s\"", pTokenData);
        return NULL;
    }
    p1 += strlen(pPrefix);
    // p1 now points to the start of the substring

    char *p2 = strstr(p1, pSuffix );
    if (!p2)
    {
        app_tracef("ERROR: ExtractSubstring() Cannot find end of token in \"%s\"", pTokenData);
        return NULL;
    }
    // p1 now points to the first character following the substring
    substringLen = p2-p1;

    pSubstring = (char *)malloc (substringLen+1);
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
        return 2401;
    }
    if (strlen(pIBRand->szPassword) == 0)
    {
        app_tracef("ERROR: Password is mandatory, but not supplied. Aborting.");
        return 2402;
    }
    if (strlen(pIBRand->szBaseUrl) == 0)
    {
        // Parameter error
        app_tracef("ERROR: URL is mandatory, but not supplied. Aborting.");
        return 2403;
    }
    return 0;
}

//-----------------------------------------------------------------------
// InitialiseCurl
//-----------------------------------------------------------------------
int InitialiseCurl(tIB_INSTANCEDATA *pIBRand)
{
    //app_tracef("{B}");
    //////////////////////////////
    // Initialise libcurl
    //////////////////////////////
    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    //app_tracef("{C}");
    pIBRand->hCurl = curl_easy_init();
    if (!pIBRand->hCurl)
    {
      app_tracef("ERROR: Library initialisation failed");
      return 2102;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
    {
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_VERBOSE, 1);
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

    //app_tracef("{A1}");
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

    //app_tracef("{A2}");
    // TokenData is something of the form (without the EOLs)...
    // {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTc1MzgzOTI5LCJleHAiOjE1NzU0NzAzMjksImlhdCI6MTU3NTM4MzkyOSwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.DvrJew9dLYVgmzB36N8LgRT1zT4hJsDtr0pjG_8WJBs",
    //  "notBefore":"2019-12-03T14:38:49.10979Z",
    //  "notAfter":"2019-12-04T14:38:49.10979Z"}

    pIBRand->pRealToken = ExtractSubstring(pIBRand->Token.pData, "\"token\":\"", "\"");
    if (!pIBRand->pRealToken)
    {
      app_tracef("ERROR: Cannot find token in TokenData pData=[%s]", pIBRand->Token.pData);
      //app_tracef("{A3}");
      return 2301;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: pRealToken = [%s]", pIBRand->pRealToken);
    }

    //fprintf(stderr, "DEBUG: Token.pData=[%s]\n", pIBRand->Token.pData);
    //fprintf(stderr, "DEBUG: pRealToken=[%s]\n", pIBRand->pRealToken);

    pIBRand->fAuthenticated = TRUE;

    //app_tracef("{A4}");
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
    // Cleanup
    //////////////////////////////
    if (pIBRand->pRealToken)
    {
        free(pIBRand->pRealToken);
    }
    if (pIBRand->ResultantData.pData)
    {
        free(pIBRand->ResultantData.pData);
        pIBRand->ResultantData.cbData = 0;
        pIBRand->ResultantData.pData = NULL;
    }
    if (pIBRand->Token.pData)
    {
        free(pIBRand->Token.pData);
        pIBRand->Token.cbData = 0;
        pIBRand->Token.pData = NULL;
    }
    //app_tracef("{j}");
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
#if (USE_CONFIG==CONFIG_HARDCODED)
static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    int rc;
    if (!pIBRand)
    {
        return 2101;
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
        return 2101;
    }

    //////////////////////////////////////
    // Get values from config file
    /////////////////////////////////////
    char *szFilename;
    FILE *hConfigFile;
    int tempval = 0;

    rc = my_openSimpleConfigFile(szConfigFilename, &hConfigFile);
    if (rc)
    {
        app_tracef("ERROR: OpenConfigFile error %d", rc);
        return rc;
    }
    app_tracef("INFO: Configuration file (SIMPLE format) [%s]", szConfigFilename);
    if (hConfigFile)
    {
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHTYPE"            , pIBRand->szAuthType            , sizeof(pIBRand->szAuthType           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHTYPE"            , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "SIMPLE"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHURL"             , pIBRand->szAuthUrl             , sizeof(pIBRand->szAuthUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHURL"             , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "https://ironbridgeapi.com/login"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHUSER"            , pIBRand->szUsername            , sizeof(pIBRand->szUsername           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHUSER"            , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Pa55w0rd"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHPSWD"            , pIBRand->szPassword            , sizeof(pIBRand->szPassword           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHPSWD"            , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Username"
        rc = my_readSimpleConfigFileInt (hConfigFile, "AUTHRETRYDELAY"      , &pIBRand->authRetryDelay                                                ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHRETRYDELAY"      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "BASEURL"             , pIBRand->szBaseUrl             , sizeof(pIBRand->szBaseUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BASEURL"             , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "ironbridgeapi.com/api" or "192.168.9.128:6502/v1/ironbridge/api"
        rc = my_readSimpleConfigFileInt (hConfigFile, "BYTESPERREQUEST"     , &pIBRand->bytesPerRequest                                               ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BYTESPERREQUEST"     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 16;
        rc = my_readSimpleConfigFileInt (hConfigFile, "RETRIEVALRETRYDELAY" , &pIBRand->retrievalRetryDelay                                           ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "RETRIEVALRETRYDELAY" , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGETYPE"         , pIBRand->szStorageType         , sizeof(pIBRand->szStorageType        ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGETYPE"         , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. FILE, MEMORY, MYSQL etc
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEDATAFORMAT"   , pIBRand->szStorageDataFormat   , sizeof(pIBRand->szStorageDataFormat  ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEDATAFORMAT"   , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. RAW, BASE64, HEX
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEFILENAME"     , pIBRand->szStorageFilename     , sizeof(pIBRand->szStorageFilename    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEFILENAME"     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/var/lib/ibrand/ibrand_data.bin"
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGELOCKFILEPATH" , pIBRand->szStorageLockfilePath , sizeof(pIBRand->szStorageLockfilePath) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOCKFILEPATH" , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/tmp"
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGEHIGHWATERMARK", &pIBRand->storageHighWaterMark                                          ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEHIGHWATERMARK", rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 1038336 (1MB)
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGELOWWATERMARK" , &pIBRand->storageLowWaterMark                                           ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOWWATERMARK" , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 102400 (100KB)
        rc = my_readSimpleConfigFileInt (hConfigFile, "IDLEDELAY"           , &pIBRand->idleDelay                                                     ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "IDLEDELAY"           , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileInt (hConfigFile, "VERBOSE"             , &tempval                                                                ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "VERBOSE"             , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        pIBRand->fVerbose = (unsigned char)tempval;
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
    return 0;

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
    fprintf(stdout, "IronBridge(tm) IBRand Service v0.30\n");
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
                app_tracef("ERROR: RNG failed with rc=%d. Will try again in %d seconds", rc, pIBRand->retrievalRetryDelay);
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
