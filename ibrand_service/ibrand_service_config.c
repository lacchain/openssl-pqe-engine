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

#include "my_utilslib.h"

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


#if (USE_CONFIG==CONFIG_HARDCODED)
int ReadConfig(char *szConfigFilename, tIB_CONFIGDATA *pIBConfig, size_t secretKeyBytes, size_t publicKeyBytes)
{
    int rc;
    if (!pIBConfig)
    {
        return 2290;
    }

    UNUSED_PARAM(szConfigFilename);

    app_tracef("WARNING: Configuration from hardcode values");

    //////////////////////////////////////
    // Hardcoded values for testing
    /////////////////////////////////////
    strcpy(pIBConfig->szAuthType            , "SIMPLE");
    strcpy(pIBConfig->szAuthUrl             , "ironbridgeapi.com/api/login");
    strcpy(pIBConfig->szUsername            , "Fred");
    strcpy(pIBConfig->szPassword            , "Pa55w0rd");
    strcpy(pIBConfig->szAuthSSLCertFile     , "/etc/ssl/certs/client_cert.pem");
    strcpy(pIBConfig->szAuthSSLCertType     , "PEM");
    strcpy(pIBConfig->szAuthSSLKeyFile      , "/etc/ssl/private/client_key.pem");
    pIBConfig->authRetryDelay               = 15;

    strcpy(pIBConfig->szBaseUrl             , "ironbridgeapi.com/api");
    pIBConfig->bytesPerRequest              = 16;
    pIBConfig->retrievalRetryDelay          = 3;

    strcpy(pIBConfig->szStorageType         , "FILE");
    strcpy(pIBConfig->szStorageDataFormat   , "RAW"); // "RAW", "BASE64", "HEX" (todo)
    strcpy(pIBConfig->szStorageFilename     , "/var/lib/ibrand/ibrand_data.bin");
    strcpy(pIBConfig->szStorageLockfilePath , "/tmp");
    strcpy(pIBConfig->shMemBackingFilename  , "shmem_ibrand01"); // e.g. /dev/shm/shmem_ibrand01
    pIBConfig->shMemStorageSize             = 100*1024;
    strcpy(pIBConfig->shMemSemaphoreName    , "sem_ibrand01");
    pIBConfig->storageHighWaterMark         = 102400; // 1038336; // 1MB
    pIBConfig->storageLowWaterMark          = 10240; // 102400; // 100KB
    pIBConfig->idleDelay                    = 10;
    pIBConfig->secretKeyBytes               = secretKeyBytes;
    pIBConfig->publicKeyBytes               = publicKeyBytes;

    pIBConfig->useSecureRng                 = true;
    strcpy(pIBConfig->clientSetupOOBFilename       , "");
    strcpy(pIBConfig->ourKemSecretKeyFilename      , "");
    //strcpy(pIBConfig->theirSigningPublicKeyFilename, "");

    //pIBConfig->fVerbose                     = 0x03;
    SET_BIT(pIBConfig->fVerbose, DBGBIT_STATUS );
    SET_BIT(pIBConfig->fVerbose, DBGBIT_CONFIG );
    SET_BIT(pIBConfig->fVerbose, DBGBIT_AUTH   );
    SET_BIT(pIBConfig->fVerbose, DBGBIT_DATA   );
    SET_BIT(pIBConfig->fVerbose, DBGBIT_CURL   );

    rc = ValidateSettings(pIBConfig);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }
    return 0;
}
#elif (USE_CONFIG==CONFIG_SIMPLE)
int ReadConfig(char *szConfigFilename, tIB_CONFIGDATA *pIBConfig, size_t secretKeyBytes, size_t publicKeyBytes)
{
    int rc;
    if (!pIBConfig)
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
    //app_tracef("INFO: Configuration file (SIMPLE format) [%s]", szConfigFilename);
    if (hConfigFile)
    {
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHTYPE"                     , pIBConfig->szAuthType            , sizeof(pIBConfig->szAuthType           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHTYPE"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "SIMPLE"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHURL"                      , pIBConfig->szAuthUrl             , sizeof(pIBConfig->szAuthUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHURL"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "https://ironbridgeapi.com/login"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHUSER"                     , pIBConfig->szUsername            , sizeof(pIBConfig->szUsername           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHUSER"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Pa55w0rd"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHPSWD"                     , pIBConfig->szPassword            , sizeof(pIBConfig->szPassword           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHPSWD"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Username"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHSSLCERTFILE"              , pIBConfig->szAuthSSLCertFile     , sizeof(pIBConfig->szAuthSSLCertFile    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHSSLCERTFILE"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/etc/ssl/certs/client_cert.pem"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHSSLCERTTYPE"              , pIBConfig->szAuthSSLCertType     , sizeof(pIBConfig->szAuthSSLCertType    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHSSLCERTTYPE"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "PEM"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHSSLKEYFILE"               , pIBConfig->szAuthSSLKeyFile      , sizeof(pIBConfig->szAuthSSLKeyFile     ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHSSLKEYFILE"               , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/etc/ssl/private/client_key.pem"
        rc = my_readSimpleConfigFileInt (hConfigFile, "AUTHRETRYDELAY"               , &pIBConfig->authRetryDelay                                                  ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHRETRYDELAY"               , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "BASEURL"                      , pIBConfig->szBaseUrl             , sizeof(pIBConfig->szBaseUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BASEURL"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "ironbridgeapi.com/api" or "192.168.9.128:6502/v1/ironbridge/api"
        rc = my_readSimpleConfigFileInt (hConfigFile, "BYTESPERREQUEST"              , &pIBConfig->bytesPerRequest                                                 ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BYTESPERREQUEST"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 16;
        rc = my_readSimpleConfigFileInt (hConfigFile, "RETRIEVALRETRYDELAY"          , &pIBConfig->retrievalRetryDelay                                             ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "RETRIEVALRETRYDELAY"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGETYPE"                  , pIBConfig->szStorageType         , sizeof(pIBConfig->szStorageType        ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGETYPE"                  , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. FILE, MEMORY, MYSQL etc
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEDATAFORMAT"            , pIBConfig->szStorageDataFormat   , sizeof(pIBConfig->szStorageDataFormat  ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEDATAFORMAT"            , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. RAW, BASE64, HEX
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEFILENAME"              , pIBConfig->szStorageFilename     , sizeof(pIBConfig->szStorageFilename    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEFILENAME"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/var/lib/ibrand/ibrand_data.bin"
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGELOCKFILEPATH"          , pIBConfig->szStorageLockfilePath , sizeof(pIBConfig->szStorageLockfilePath) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOCKFILEPATH"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/tmp"
        rc = my_readSimpleConfigFileStr (hConfigFile, "SHMEMBACKINGFILENAME"         , pIBConfig->shMemBackingFilename  , sizeof(pIBConfig->shMemBackingFilename ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "SHMEMBACKINGFILENAME"         , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "shmem_ibrand01" // e.g. /dev/shm/shmem_ibrand01
        rc = my_readSimpleConfigFileLong(hConfigFile, "SHMEMSTORAGESIZE"             , &pIBConfig->shMemStorageSize                                                ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "SHMEMSTORAGESIZE"             , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. (100*1024)
        rc = my_readSimpleConfigFileStr (hConfigFile, "SHMEMSEMAPHORENAME"           , pIBConfig->shMemSemaphoreName    , sizeof(pIBConfig->shMemSemaphoreName   ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "SHMEMSEMAPHORENAME"           , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "sem_ibrand01"
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGEHIGHWATERMARK"         , &pIBConfig->storageHighWaterMark                                            ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEHIGHWATERMARK"         , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 1038336 (1MB)
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGELOWWATERMARK"          , &pIBConfig->storageLowWaterMark                                             ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOWWATERMARK"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 102400 (100KB)
        rc = my_readSimpleConfigFileInt (hConfigFile, "IDLEDELAY"                    , &pIBConfig->idleDelay                                                       ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "IDLEDELAY"                    , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileByte(hConfigFile, "VERBOSE"                      , &pIBConfig->fVerbose                                                        ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "VERBOSE"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        rc = my_readSimpleConfigFileByte(hConfigFile, "USESECURERNG"                 , &pIBConfig->useSecureRng                                                    ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "USESECURERNG"                 , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        rc = my_readSimpleConfigFileStr (hConfigFile, "CLIENTSETUPOOBFILENAME"       , pIBConfig->clientSetupOOBFilename       , sizeof(pIBConfig->clientSetupOOBFilename)        ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "CLIENTSETUPOOBFILENAME"       , rc); my_closeSimpleConfigFile(hConfigFile); return rc; }
        rc = my_readSimpleConfigFileStr (hConfigFile, "OURKEMSECRETKEYFILENAME"      , pIBConfig->ourKemSecretKeyFilename      , sizeof(pIBConfig->ourKemSecretKeyFilename)       ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "OURKEMSECRETKEYFILENAME"      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; }
        //rc = my_readSimpleConfigFileStr (hConfigFile, "THEIRSIGNINGPUBLICKEYFILENAME", pIBConfig->theirSigningPublicKeyFilename, sizeof(pIBConfig->theirSigningPublicKeyFilename) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "THEIRSIGNINGPUBLICKEYFILENAME", rc); my_closeSimpleConfigFile(hConfigFile); return rc; }

        pIBConfig->secretKeyBytes = secretKeyBytes;
        pIBConfig->publicKeyBytes = publicKeyBytes;
        my_closeSimpleConfigFile(hConfigFile);
    }

    rc = ValidateSettings(pIBConfig);
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
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_CONFIGDATA *pIBConfig)
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
                        my_strlcpy(pIBConfig->szAuthType, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHURL")==0)
                    {
                        my_strlcpy(pIBConfig->szAuthUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHUSER")==0)
                    {
                        my_strlcpy(pIBConfig->szUsername, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szUsername));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHPSWD")==0)
                    {
                        my_strlcpy(pIBConfig->szPassword, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szPassword));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLCERTFILE")==0)
                    {
                        my_strlcpy(pIBConfig->szAuthSSLCertFile, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthSSLCertFile));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLCERTTYPE")==0)
                    {
                        my_strlcpy(pIBConfig->szAuthSSLCertType, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szAuthSSLCertType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLKEYFILE" )==0)
                    {
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
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"USESECURERNG")==0)
                    {
                        pIBConfig->useSecureRng = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"CLIENTSETUPOOBFILENAME")==0)
                    {
                        my_strlcpy(pIBConfig->clientSetupOOBFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->clientSetupOOBFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"OURKEMSECRETKEYFILENAME")==0)
                    {
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
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"BASEURL")==0)
                    {
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
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"STORAGETYPE")==0)
                    {
                        my_strlcpy(pIBConfig->szStorageType, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEDATAFORMAT")==0)
                    {
                        my_strlcpy(pIBConfig->szStorageDataFormat, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageDataFormat));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEFILENAME")==0)
                    {
                        my_strlcpy(pIBConfig->szStorageFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOCKFILEPATH")==0)
                    {
                        my_strlcpy(pIBConfig->szStorageLockfilePath, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->szStorageLockfilePath));
                    }

                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_BACKINGFILENAME")==0)
                    {
                        my_strlcpy(pIBConfig->shMemBackingFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->shMemBackingFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_STORAGESIZE")==0)
                    {
                        pIBConfig->shMemStorageSize = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_SEMAPHORENAME")==0)
                    {
                        my_strlcpy(pIBConfig->shMemSemaphoreName, childJson->pairs[jj].value->stringValue, sizeof(pIBConfig->shMemSemaphoreName));
                    }

                    else if (strcmp(childJson->pairs[jj].key,"STORAGEHIGHWATERMARK")==0)
                    {
                        pIBConfig->storageHighWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOWWATERMARK")==0)
                    {
                        pIBConfig->storageLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
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
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

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
        app_tracef("ERROR: Error %d parsing JSON config\n", rc);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
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

#endif // USE_CONFIG


void PrintConfig(tIB_CONFIGDATA *pIBConfig)
{
    // Hide the password against wandering eyes
    char hiddenPassword[32];

    memset(hiddenPassword, 0, sizeof(hiddenPassword));
    for (int ii=0; ii<my_minimum(sizeof(hiddenPassword)-1,strlen(pIBConfig->szPassword)); ii++)
       hiddenPassword[ii] = '*';

    app_tracef("fVerbose              =[%u]" , pIBConfig->fVerbose              ); // Bitmapped field
    app_tracef("szAuthType            =[%s]" , pIBConfig->szAuthType            ); // char          szAuthType               [16]   // "SIMPLE";
    app_tracef("szAuthUrl             =[%s]" , pIBConfig->szAuthUrl             ); // char          szAuthUrl                [128]  // "https://ironbridgeapi.com/login";
    app_tracef("szUsername            =[%s]" , pIBConfig->szUsername            ); // char          szUsername               [32]
    app_tracef("szPassword            =[%s]" , hiddenPassword                 ); // char          szPassword               [32]
    app_tracef("szAuthSSLCertFile     =[%s]" , pIBConfig->szAuthSSLCertFile     ); // char          szAuthSSLCertFile        [128]  // "/etc/ssl/certs/client_cert.pem"
    app_tracef("szAuthSSLCertType     =[%s]" , pIBConfig->szAuthSSLCertType     ); // char          szAuthSSLCertType        [32]   // "PEM"
    app_tracef("szAuthSSLKeyFile      =[%s]" , pIBConfig->szAuthSSLKeyFile      ); // char          szAuthSSLKeyFile         [128]  // "/etc/ssl/private/client_key.pem"
    app_tracef("authRetryDelay        =[%d]" , pIBConfig->authRetryDelay        ); // int           authRetryDelay
    //app_tracef("ourKemSecretKey       =[%s]" , hiddenKemSecretKey             );
    //app_tracef("theirSigningPublicKey =[%s]" , pIBRand->theirSigningPublicKey );
    app_tracef("useSecureRng          =[%u]" , pIBConfig->useSecureRng          );
    app_tracef("szBaseUrl             =[%s]" , pIBConfig->szBaseUrl             ); // char          szBaseUrl                [128]  // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    app_tracef("bytesPerRequest       =[%d]" , pIBConfig->bytesPerRequest       ); // int           bytesPerRequest                 // 16
    app_tracef("retrievalRetryDelay   =[%d]" , pIBConfig->retrievalRetryDelay   ); // int           retrievalRetryDelay             //
    app_tracef("szStorageType         =[%s]" , pIBConfig->szStorageType         ); // char[16]      // "FILE", "SHMEM"
    app_tracef("szStorageDataFormat   =[%s]" , pIBConfig->szStorageDataFormat   ); // char[16]      // RAW, BASE64, HEX
    app_tracef("szStorageFilename     =[%s]" , pIBConfig->szStorageFilename     ); // char[128]     // "/var/lib/ibrand/ibrand_data.bin"
    app_tracef("szStorageLockfilePath =[%s]" , pIBConfig->szStorageLockfilePath ); // char[128]     // "/tmp"
    app_tracef("shMemBackingFilename  =[%s]" , pIBConfig->shMemBackingFilename  ); // char[128]     // "shmem_ibrand01" e.g. /dev/shm/shmem_ibrand01
    app_tracef("shMemStorageSize      =[%ld]", pIBConfig->shMemStorageSize      ); // long          // (100*1024)
    app_tracef("shMemSemaphoreName    =[%s]" , pIBConfig->shMemSemaphoreName    ); // char[16]      // "sem_ibrand01"
    app_tracef("storageHighWaterMark  =[%ld]", pIBConfig->storageHighWaterMark  ); // long          // 1038336; // 1MB
    app_tracef("storageLowWaterMark   =[%ld]", pIBConfig->storageLowWaterMark   ); // long          // 102400; // 100KB
    app_tracef("idleDelay             =[%d]" , pIBConfig->idleDelay             ); // int           //

    app_tracef("secretKeyBytes        =[%u]" , pIBConfig->secretKeyBytes        );
    app_tracef("publicKeyBytes        =[%u]" , pIBConfig->publicKeyBytes        );
}

static bool __ParseJsonOOBData(const char *szJsonString, tIB_OOBDATA *pOobData)
{
    JSONObject *json2 = NULL;
    const int localConfigTracing = false;

    json2 = my_parseJSON(szJsonString);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse OOB JSON string\n");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localConfigTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s\r\n", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");

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
                pOobData->hexData.pData = malloc(buffer_size);
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
                pOobData->expiryDate.pData = malloc(buffer_size);
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
    char *szJsonString = malloc(jsonData.cbData+1);
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
    if (!szJsonString)
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
