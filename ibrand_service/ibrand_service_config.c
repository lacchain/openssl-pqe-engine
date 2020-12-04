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

#include "../ibrand_common/my_utilslib.h"

#include "ibrand_service.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_config.h"

typedef struct tagIB_OOBDATA
{
    int           requiredSegments;  // "requiredSegments": "1",
    int           segmentNumber;     // "segmentNumber": "1",
    tLSTRING      hexData;           // "hexData": "00112233445566778899AABBCCDDEEFF....",
    tLSTRING      expiryDate;        // "expiryDate": "02/09/2020 18:10:38",
    int           checkSum;          // "checkSum": "39776"
} tIB_OOBDATA;


//-----------------------------------------------------------------------
// ValidateSettings
//-----------------------------------------------------------------------
int ValidateSettings(tIB_CONFIGDATA *pIBConfig)
{
    if (strlen(pIBConfig->szUsername) == 0)
    {
        app_tracef("ERROR: Username is mandatory, but not supplied. Aborting.");
        return 2250;
    }
    if (strlen(pIBConfig->szPassword) == 0)
    {
        app_tracef("ERROR: Password is mandatory, but not supplied. Aborting.");
        return 2251;
    }
    if (strlen(pIBConfig->szBaseUrl) == 0)
    {
        // Parameter error
        app_tracef("ERROR: URL is mandatory, but not supplied. Aborting.");
        return 2252;
    }
    return 0;
}

static int localDebugTracing = false;

static bool __StringLengthExceeded(JSONPair *item, size_t maxLen)
{
    size_t itemLen = strlen(item->value->stringValue);
    if (itemLen > maxLen)
    {
        app_tracef("ERROR: Length of item %s (%d) exceeds maxlen (%d)", item->key, itemLen, maxLen);
        return true;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_CONFIGDATA *pIBConfig)
{
    JSONObject *json2;

    json2 = my_parseJSON(szJsonConfig);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse JSON string");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localDebugTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");

        if (strcmp(json2->pairs[ii].key,"AuthSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localDebugTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"AUTHTYPE")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szAuthType)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szAuthType, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHURL")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szAuthUrl)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szAuthUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHUSER")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szUsername)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szUsername, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szUsername));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHPSWD")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szPassword)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szPassword, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szPassword));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLCERTFILE")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szAuthSSLCertFile)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szAuthSSLCertFile, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthSSLCertFile));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLCERTTYPE")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szAuthSSLCertType)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szAuthSSLCertType, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthSSLCertType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLKEYFILE" )==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szAuthSSLKeyFile)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szAuthSSLKeyFile , childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthSSLKeyFile ));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHRETRYDELAY")==0)
                    {
                        pIBConfig->authRetryDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"SecuritySettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localDebugTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"USESECURERNG")==0)
                    {
                        pIBConfig->useSecureRng = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"PREFERRED_KEM_ALGORITHM")==0)
                    {
                        pIBConfig->preferredKemAlgorithm = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"CLIENTSETUPOOBFILENAME")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->clientSetupOOBFilename)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->clientSetupOOBFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->clientSetupOOBFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"OURKEMSECRETKEYFILENAME")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->ourKemSecretKeyFilename)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->ourKemSecretKeyFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->ourKemSecretKeyFilename));
                    }
                    //else if (strcmp(childJson->pairs[jj].key,"THEIRSIGNINGPUBLICKEYFILENAME")==0)
                    //{
                    //    my_strlcpy(pIBConfig->theirSigningPublicKeyFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->theirSigningPublicKeyFilename));
                    //}
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"CommsSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localDebugTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"BASEURL")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szBaseUrl)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szBaseUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szBaseUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"BYTESPERREQUEST")==0)
                    {
                        pIBConfig->bytesPerRequest = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"RETRIEVALRETRYDELAY")==0)
                    {
                        pIBConfig->retrievalRetryDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"StorageSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localDebugTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"STORAGETYPE")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szStorageType)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szStorageType, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageType));
                    }

                    else if (strcmp(childJson->pairs[jj].key,"FILE_DATAFORMAT")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szStorageDataFormat)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szStorageDataFormat, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageDataFormat));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_FILENAME")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szStorageFilename)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szStorageFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_LOCKFILEPATH")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->szStorageLockfilePath)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->szStorageLockfilePath, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageLockfilePath));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_HIGHWATERMARK")==0)
                    {
                        pIBConfig->storageHighWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_LOWWATERMARK")==0)
                    {
                        pIBConfig->storageLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }

                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_BACKINGFILENAME")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->shMemBackingFilename)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->shMemBackingFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->shMemBackingFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_SEMAPHORENAME")==0)
                    {
                        if (__StringLengthExceeded(&childJson->pairs[jj], sizeof(pIBConfig->shMemSemaphoreName)-1))
                        {
                            return false;
                        }
                        my_strlcpy(pIBConfig->shMemSemaphoreName, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->shMemSemaphoreName));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_STORAGESIZE")==0)
                    {
                        pIBConfig->shMemStorageSize = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_LOWWATERMARK")==0)
                    {
                        pIBConfig->shMemLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }

                    else if (strcmp(childJson->pairs[jj].key,"IDLEDELAY")==0)
                    {
                        pIBConfig->idleDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"GeneralSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localDebugTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"LOGGING_VERBOSITY")==0)
                    {
                        pIBConfig->fVerbose = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}

int ReadConfig(char *szConfigFilename, tIB_CONFIGDATA *pIBConfig, size_t secretKeyBytes, size_t publicKeyBytes)
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
    //app_tracef("INFO: Configuration file (JSON format) [%s] (%u bytes)", szConfigFilename, strlen(szJsonConfig));

    rc = __ParseJsonConfig(szJsonConfig, pIBConfig);
    if (!rc)
    {
        app_tracef("ERROR: Error parsing JSON config");
        if (szJsonConfig) free(szJsonConfig);
        return 10117;
    }
    if (szJsonConfig) free(szJsonConfig);

    pIBConfig->secretKeyBytes = secretKeyBytes;
    pIBConfig->publicKeyBytes = publicKeyBytes;

    rc = ValidateSettings(pIBConfig);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }

    return 0;
}

void PrintConfig(tIB_CONFIGDATA *pIBConfig)
{
    // Hide the password against wandering eyes
    char hiddenPassword[32];

    memset(hiddenPassword, 0, sizeof(hiddenPassword));
    for (int ii=0; ii<my_minimum(sizeof(hiddenPassword)-1,strlen(pIBConfig->szPassword)); ii++)
       hiddenPassword[ii] = '*';

    app_tracef("fVerbose              =[%u]" , pIBConfig->fVerbose              ); // Bitmapped field
    app_tracef("szAuthType            =[%s]" , pIBConfig->szAuthType            ); // char          szAuthType               [16]        // "SIMPLE";
    app_tracef("szAuthUrl             =[%s]" , pIBConfig->szAuthUrl             ); // char          szAuthUrl                [_MAX_URL]  // "https://ironbridgeapi.com/login";
    app_tracef("szUsername            =[%s]" , pIBConfig->szUsername            ); // char          szUsername               [32]
    app_tracef("szPassword            =[%s]" , hiddenPassword                   ); // char          szPassword               [32]
    app_tracef("szAuthSSLCertFile     =[%s]" , pIBConfig->szAuthSSLCertFile     ); // char          szAuthSSLCertFile        [_MAX_PATH] // "/etc/ssl/certs/client_cert.pem"
    app_tracef("szAuthSSLCertType     =[%s]" , pIBConfig->szAuthSSLCertType     ); // char          szAuthSSLCertType        [32]        // "PEM"
    app_tracef("szAuthSSLKeyFile      =[%s]" , pIBConfig->szAuthSSLKeyFile      ); // char          szAuthSSLKeyFile         [_MAX_PATH] // "/etc/ssl/private/client_key.pem"
    app_tracef("authRetryDelay        =[%d]" , pIBConfig->authRetryDelay        ); // int           authRetryDelay
    //app_tracef("ourKemSecretKey       =[%s]" , hiddenKemSecretKey             );
    //app_tracef("theirSigningPublicKey =[%s]" , pIBRand->theirSigningPublicKey );
    app_tracef("useSecureRng          =[%u]" , pIBConfig->useSecureRng          );
    app_tracef("szBaseUrl             =[%s]" , pIBConfig->szBaseUrl             ); // char          szBaseUrl                [_MAX_URL]  // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    app_tracef("bytesPerRequest       =[%d]" , pIBConfig->bytesPerRequest       ); // int           bytesPerRequest                      // 16
    app_tracef("retrievalRetryDelay   =[%d]" , pIBConfig->retrievalRetryDelay   ); // int           retrievalRetryDelay                  //
    app_tracef("szStorageType         =[%s]" , pIBConfig->szStorageType         ); // char[16]      // "FILE", "SHMEM"
    app_tracef("szStorageDataFormat   =[%s]" , pIBConfig->szStorageDataFormat   ); // char[16]      // RAW, BASE64, HEX
    app_tracef("szStorageFilename     =[%s]" , pIBConfig->szStorageFilename     ); // char[_MAX_PATH] // "/var/lib/ibrand/ibrand_data.bin"
    app_tracef("szStorageLockfilePath =[%s]" , pIBConfig->szStorageLockfilePath ); // char[_MAX_PATH] // "/tmp"
    app_tracef("storageHighWaterMark  =[%ld]", pIBConfig->storageHighWaterMark  ); // long          // 1038336; // 1MB
    app_tracef("storageLowWaterMark   =[%ld]", pIBConfig->storageLowWaterMark   ); // long          // 102400; // 100KB
    app_tracef("shMemBackingFilename  =[%s]" , pIBConfig->shMemBackingFilename  ); // char[_MAX_PATH] // "shmem_ibrand01" e.g. /dev/shm/shmem_ibrand01
    app_tracef("shMemSemaphoreName    =[%s]" , pIBConfig->shMemSemaphoreName    ); // char[16]      // "sem_ibrand01"
    app_tracef("shMemStorageSize      =[%ld]", pIBConfig->shMemStorageSize      ); // long          // (100*1024)
    app_tracef("shMemLowWaterMark     =[%ld]", pIBConfig->shMemLowWaterMark     ); // long          // 102400; // 100KB
    app_tracef("idleDelay             =[%d]" , pIBConfig->idleDelay             ); // int           //

    app_tracef("secretKeyBytes        =[%u]" , pIBConfig->secretKeyBytes        );
    app_tracef("publicKeyBytes        =[%u]" , pIBConfig->publicKeyBytes        );
}

static bool __ParseJsonOOBData(const char *szJsonString, tIB_OOBDATA *pOobData)
{
    JSONObject *json2;

    json2 = my_parseJSON(szJsonString);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse OOB JSON string");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localDebugTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");

        if (json2->pairs[ii].type == JSON_STRING)
        {
            if (strcmp(json2->pairs[ii].key,"requiredSegments")==0)
            {
                pOobData->requiredSegments = atoi(json2->pairs[ii].value->stringValue);
            }
            else if (strcmp(json2->pairs[ii].key,"segmentNumber")==0)
            {
                pOobData->segmentNumber = atoi(json2->pairs[ii].value->stringValue);
            }
            else if (strcmp(json2->pairs[ii].key,"hexData")==0)
            {
                // json2->pairs[ii].value->stringValue is a malloc'd zstring which will be freed later in my_freeJSONFromMemory(), so we must duplicate here
                // Essentially, a strdup...
                size_t buffer_size = strlen(json2->pairs[ii].value->stringValue);
                pOobData->hexData.pData = (char *)malloc(buffer_size);
                if (!pOobData->hexData.pData)
                {
                    app_tracef("ERROR: Failed to allocate %u bytes for pOobData->hexData", buffer_size);
                    return false;
                }
                memcpy(pOobData->hexData.pData, json2->pairs[ii].value->stringValue, buffer_size);
                pOobData->hexData.cbData = buffer_size;
            }
            else if (strcmp(json2->pairs[ii].key,"expiryDate")==0)
            {
                // json2->pairs[ii].value->stringValue is a malloc'd zstring which will be freed later in my_freeJSONFromMemory(), so we must duplicate here
                // Essentially, a strdup...
                size_t buffer_size = strlen(json2->pairs[ii].value->stringValue);
                pOobData->expiryDate.pData = (char *)malloc(buffer_size);
                if (!pOobData->expiryDate.pData)
                {
                    app_tracef("ERROR: Failed to allocate %u bytes for pOobData->expiryDate", buffer_size);
                    return false;
                }
                memcpy(pOobData->expiryDate.pData, json2->pairs[ii].value->stringValue, buffer_size);
                pOobData->expiryDate.cbData = buffer_size;
            }
            else if (strcmp(json2->pairs[ii].key,"checkSum")==0)
            {
                pOobData->checkSum = atoi(json2->pairs[ii].value->stringValue);
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}

int GetBinaryDataFromOOBFile(char *szSrcFilename, tLSTRING *pDestBinaryData)
{
    int rc;
    tLSTRING jsonData;

    rc = ReadContentsOfFile(szSrcFilename, &jsonData, NO_EXPECTATION_OF_FILESIZE );
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to read contents of OOB file \"%s\"", szSrcFilename);
        return rc;
    }
    // We need a zstring for the json parser
    char *szJsonString = (char *)malloc(jsonData.cbData+1);
    if (!szJsonString)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for szJsonString", jsonData.cbData+1);
        return 2083;
    }
    memset(szJsonString, 0, jsonData.cbData+1);
    my_strlcpy(szJsonString, jsonData.pData, jsonData.cbData);

    // And release the memory malloc'd by ReadContentsOfFile, since it is no longer needed
    free(jsonData.pData);
    jsonData.pData = NULL;
    jsonData.cbData = 0;

    // Parse OOB File, resulting in a KEM private Key
    // For example...
    // {
    //   "requiredSegments": "1",
    //   "segmentNumber": "1",
    //   "hexData": "8C1E585A...4A0587F7",
    //   "expiryDate": "02/09/2020 18:10:38",
    //   "checkSum": "39776"
    // }
    tIB_OOBDATA *pOobData = (tIB_OOBDATA *)malloc(sizeof(tIB_OOBDATA));
    if (!pOobData)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for OOB Data", sizeof(tIB_OOBDATA));
        return 2083;
    }
    bool success = __ParseJsonOOBData(szJsonString, pOobData);
    if (!success)
    {
        app_tracef("ERROR: Failed to parse OOB json string");
        free(pOobData);
        pOobData = NULL;
        return 2084;
    }

    success = DecodeHexString(&(pOobData->hexData), pDestBinaryData);
    if (!success)
    {
        app_tracef("ERROR: Failed to decode KEM secret key hex string");
        free(pOobData);
        pOobData = NULL;
        return 2085;
    }

    free(pOobData);
    pOobData = NULL;
    return 0;
}
