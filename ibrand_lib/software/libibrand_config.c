
// Required to include clock_gettime
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <syslog.h>

#include "libibrand_config.h"
#include "ibrand_service_shmem.h"
#include "my_utilslib.h"


tIB_INSTANCEDATA *cfgInitConfig (void)
{
    tIB_INSTANCEDATA *pIBRand;
    tERRORCODE rc;

    // =========================================================================
    // Create instance storage
    // =========================================================================
    pIBRand = malloc(sizeof(tIB_INSTANCEDATA));
    if (!pIBRand)
    {
        app_tracef("[ibrand_lib] FATAL: Failed to allocate memory for local storage. Aborting.");
        return NULL;
    }
    memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));

    char *tempPtr;
    rc = my_getFilenameFromEnvVar("IBRAND_CONF", &tempPtr);
    if (rc == ERC_OK)
    {
        my_strlcpy(pIBRand->szConfigFilename, tempPtr, sizeof(pIBRand->szConfigFilename));
        free(tempPtr);
    }
    if (strlen(pIBRand->szConfigFilename) == 0)
    {
        app_tracef("[ibrand_lib] FATAL: Configuration not specified, neither on commandline nor via an environment variable.");
        free(pIBRand);
        return NULL;
    }

    rc = cfgReadConfig(pIBRand->szConfigFilename, pIBRand);
    if (rc != ERC_OK)
    {
        app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
        app_trace_closelog();
        free(pIBRand);
        return NULL;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
    //{
    //    cfgPrintConfig(pIBRand);
    //}

    ShMem_SetBackingFilename (pIBRand->cfg.shMemBackingFilename); // char[_MAX_PATH] // "shmem_ibrand01" e.g. /dev/shm/shmem_ibrand01
    ShMem_SetStorageSize     (pIBRand->cfg.shMemStorageSize    ); // long            // (100*1024)
    ShMem_SetSemaphoreName   (pIBRand->cfg.shMemSemaphoreName  ); // char[16]        // "sem_ibrand01"

    return pIBRand;
}


////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_INSTANCEDATA *pIBRand)
{
    JSONObject *json2;
    const int localDebugTracing = false;

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
                    // None of these items are interesting for us
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
                    // None of these items are interesting for us
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
                        my_strlcpy(pIBRand->cfg.szStorageType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->cfg.szStorageType));
                    }

                    else if (strcmp(childJson->pairs[jj].key,"FILE_DATAFORMAT")==0)
                    {
                        my_strlcpy(pIBRand->cfg.szStorageDataFormat, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->cfg.szStorageDataFormat));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_FILENAME")==0)
                    {
                        my_strlcpy(pIBRand->cfg.szStorageFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->cfg.szStorageFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_LOCKFILEPATH")==0)
                    {
                        my_strlcpy(pIBRand->cfg.szStorageLockfilePath, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->cfg.szStorageLockfilePath));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_HIGHWATERMARK")==0)
                    {
                        pIBRand->cfg.storageHighWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"FILE_LOWWATERMARK")==0)
                    {
                        pIBRand->cfg.storageLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }

                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_BACKINGFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->cfg.shMemBackingFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->cfg.shMemBackingFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_SEMAPHORENAME")==0)
                    {
                        my_strlcpy(pIBRand->cfg.shMemSemaphoreName, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->cfg.shMemSemaphoreName));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_STORAGESIZE")==0)
                    {
                        pIBRand->cfg.shMemStorageSize = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"SHMEM_LOWWATERMARK")==0)
                    {
                        pIBRand->cfg.shMemLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
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
                        pIBRand->cfg.fVerbose = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}

tERRORCODE cfgReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    char *szJsonConfig;
    tERRORCODE rc;
    bool success;

    rc = my_readEntireConfigFileIntoMemory(szConfigFilename, &szJsonConfig);
    if (rc != ERC_OK)
    {
        app_tracef("ERROR: Error %d reading JSON config from file: %s", rc, szConfigFilename);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    //app_tracef("INFO: Configuration file (JSON format) [%s] (%u bytes)", szConfigFilename, strlen(szJsonConfig));

    success = __ParseJsonConfig(szJsonConfig, pIBRand);
    if (!success)
    {
        app_tracef("ERROR: Error parsing JSON config");
        if (szJsonConfig) free(szJsonConfig);
        return ERC_IBCFG_JSON_PARSE_FAILED;
    }
    if (szJsonConfig) free(szJsonConfig);

    return ERC_OK;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
char *cfgGetValue(char *szEnvVariableWithFilename, char *szKey)
{
    const char *szConfigfilePath;
    FILE *fConfFile;
    char *szRetVal = NULL;

    szConfigfilePath = getenv(szEnvVariableWithFilename);
    if (!szConfigfilePath)
    {
        app_tracef("ERROR: Cannot find environment variable: %s", szEnvVariableWithFilename);
        return NULL;
    }

    fConfFile = fopen(szConfigfilePath, "rt");
    if (fConfFile == NULL)
    {
        app_tracef("ERROR: Cannot open config file: %s", szConfigfilePath);
        return NULL;
    }

    char line[1024] = {0};
    while (!feof(fConfFile))
    {
        memset(line, 0, 1024);
        char *ret = fgets(line, 1024, fConfFile);
        if (ret==NULL)
        {
            break; // EOF
        }
        if (line[0] == '#')
        {
            continue;
        }

        int len = strlen(line);
        char *pos = strchr(line, '=');
        if (pos == NULL)
        {
            continue;
        }
        char key[64] = {0};
        char val[64] = {0};

        int offset = 1;
        if (line[len-1] == '\n')
        {
            offset = 2;
        }

        strncpy(key, line, pos-line);
        strncpy(val, pos+1, line+len-offset-pos);

        //app_tracef("INFO: Found Key:Value pair:  %s:%s", key, val);

        if (strcmp(key, szKey) == 0)
        {
            szRetVal = malloc(strlen(val+1));
            if (!szRetVal)
            {
                app_tracef("ERROR: Out of memory");
                fclose(fConfFile);
                return NULL;
            }
            strcpy(szRetVal, val);
            break;
        }
    }
    if (!szRetVal)
    {
        app_tracef("ERROR: Cannot find config key: %s", szKey);
    }
    fclose(fConfFile);
    return szRetVal;
}


void cfgGetDatafilename(char *pIBDatafilename, size_t cbIBDatafilename, tIB_INSTANCEDATA *pIBRand)
{
    my_strlcpy(pIBDatafilename, pIBRand->cfg.szStorageFilename, cbIBDatafilename);
}

void cfgPrintConfig(tIB_INSTANCEDATA *pIBRand)
{
    app_tracef("fVerbose              =[%u]" , pIBRand->cfg.fVerbose              ); // unsigned char   // Bitmapped field
    app_tracef("szStorageType         =[%s]" , pIBRand->cfg.szStorageType         ); // char[16]        // "FILE", "SHMEM"
    app_tracef("szStorageDataFormat   =[%s]" , pIBRand->cfg.szStorageDataFormat   ); // char[16]        // RAW, BASE64, HEX
    app_tracef("szStorageFilename     =[%s]" , pIBRand->cfg.szStorageFilename     ); // char[_MAX_PATH] // "/var/lib/ibrand/ibrand_data.bin"
    app_tracef("szStorageLockfilePath =[%s]" , pIBRand->cfg.szStorageLockfilePath ); // char[_MAX_PATH] // "/tmp"
    app_tracef("storageHighWaterMark  =[%ld]", pIBRand->cfg.storageHighWaterMark  ); // long            // 1038336 // 1MB
    app_tracef("storageLowWaterMark   =[%ld]", pIBRand->cfg.storageLowWaterMark   ); // long            // 102400 // 100KB
    app_tracef("shMemBackingFilename  =[%s]" , pIBRand->cfg.shMemBackingFilename  ); // char[_MAX_PATH] // "shmem_ibrand01" e.g. /dev/shm/shmem_ibrand01
    app_tracef("shMemSemaphoreName    =[%s]" , pIBRand->cfg.shMemSemaphoreName    ); // char[16]        // "sem_ibrand01"
    app_tracef("shMemStorageSize      =[%ld]", pIBRand->cfg.shMemStorageSize      ); // long            // (100*1024)
    app_tracef("shMemLowWaterMark     =[%ld]", pIBRand->cfg.shMemLowWaterMark     ); // long            // 102400 // 100KB
}
