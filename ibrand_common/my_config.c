///////////////////////////////////////////////////////////////////////////////
// Various configuration utilities
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>

#include "my_utils.h"
#include "my_config.h"

int my_getFilenameFromEnvVar(const char *szConfigEnvVar, char **pszFilename)
{
    const char *szConfigfilePath;

    *pszFilename = NULL;

    if (!szConfigEnvVar)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
        return 6000;
    }

    szConfigfilePath = getenv(szConfigEnvVar); // Returns a pointer into the current environment
    if (!szConfigfilePath)
    {
        fprintf(stderr, "ERROR: Cannot find environment variable: %s\n", szConfigEnvVar);
        return 6001;
    }

    // Effectively, a strdup
    *pszFilename = malloc(strlen(szConfigfilePath));
    if (*pszFilename == NULL)
    {
        fprintf(stderr, "ERROR: Out of memory\n");
        return 6002;
    }
    strcpy(*pszFilename, szConfigfilePath);

    return 0;
}

int my_openSimpleConfigFile(char *szFilename, FILE **phConfigFile)
{
    FILE * hConfigFile = NULL;

    if (!phConfigFile)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
        return 6000;
    }

    *phConfigFile = NULL;

    hConfigFile = fopen(szFilename, "rt");
    if (hConfigFile == NULL)
    {
        //fprintf(stderr, "ERROR: Cannot open config file: %s\n", szFilename);
        return 6003;
    }

    *phConfigFile = hConfigFile;
    return 0;
}

/*
int my_openSimpleConfigFileEnv(const char *szConfigEnvVar, char **pszFilename, FILE **phConfigFile)
{
    int rc;

    if (!phConfigFile || !pszFilename)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
        return 6000;
    }

    *pszFilename = NULL;
    *phConfigFile = NULL;

    rc = my_getFilenameFromEnvVar(szConfigEnvVar, pszFilename);
    if (rc)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
        return rc;
    }

    rc = my_openSimpleConfigFile(*pszFilename, phConfigFile);
    if (rc)
    {
        //fprintf(stderr, "ERROR: Failed to open config file\n");
        return rc;
    }
    return 0;
}
*/

int my_readSimpleConfigFileStr(FILE *hConfigFile, const char *szKey, char *pDest, size_t cbDest)
{
    const int BUFSIZE = 1024;
    int found = false;
    char *pLine;

    if (!hConfigFile  || !szKey || !pDest || cbDest == 0)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
       return 6004;
    }
    pDest[0] = '\0';

    // Create a temporary buffer in which to read each line.
    pLine = malloc(BUFSIZE);
    if (!pLine)
    {
        //fprintf(stderr, "ERROR: Out of memory\n");
       return 6005;
    }
    memset(pLine, 0, BUFSIZE);

    // Ensure that we are starting at the top of the file
    rewind(hConfigFile);

    // Go through each lione of the config file looking for our Key
    while (!feof(hConfigFile))
    {
        memset(pLine, 0, BUFSIZE);
        char *ret = fgets(pLine, BUFSIZE, hConfigFile);
        if (ret==NULL)
        {
            break; // EOF
        }
        if (pLine[0] == '#')
        {
            continue;
        }

        char key[64] = {0};
        char val[64] = {0};

                                              // e.g.  mykey=myvalue\n
        int line_len = strlen(pLine);         // e.g. 14
        char *delim_pos = strchr(pLine, '='); // e.g. (pLine+5)
        if (delim_pos == NULL)
        {
            continue;
        }

        char * key_pos = pLine;
        size_t key_len = delim_pos - pLine;   // e.g. 5

        size_t offset = 1;
        if (pLine[line_len-1] == '\n')        // true
        {
            offset = 2;
        }
        char * val_pos = delim_pos + 1; // skip over '='
        size_t val_len = pLine + line_len - offset - delim_pos;

        if (key_len >= sizeof(key) || val_len >= sizeof(val))
        {
            //fprintf(stderr, "ERROR: Either a key or a value is too long\n");
            free(pLine);
            return 6006;
        }
        // Extract key portion
        my_strlcpy(key, key_pos, key_len);
        // Extract val portion
        my_strlcpy(val, val_pos, val_len);

        //fprintf(stderr, "INFO: Found Key:Value pair:  %s:%s\n", key, val);

        if (strcmp(key, szKey) == 0)
        {
            found = true;
            my_strlcpy(pDest, val, cbDest);
            break;
        }
    }
    free(pLine);

    if (!found)
    {
        //fprintf(stderr, "ERROR: Cannot find config key: %s\n", szKey);
        return 6007;
    }
    return 0;
}

int my_readSimpleConfigFileByte(FILE * hConfigFile, const char *szKey, unsigned char *pDest)
{
    int rc;
    int tempval;

    if (!hConfigFile  || !szKey || !pDest)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
       return 6007;
    }

    rc = my_readSimpleConfigFileInt(hConfigFile, szKey, &tempval);
    if (rc)
    {
        return rc;
    }
    *pDest = (unsigned char)tempval;
    return 0;
}

int my_readSimpleConfigFileInt(FILE * hConfigFile, const char *szKey, int *pDest)
{
    int rc;
    char szValue[64];

    if (!hConfigFile  || !szKey || !pDest)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
       return 6007;
    }

    rc = my_readSimpleConfigFileStr(hConfigFile, szKey, szValue, sizeof(szValue));
    if (rc)
    {
        return rc;
    }
    *pDest = atoi(szValue);
    return 0;
}

int my_readSimpleConfigFileLong(FILE * hConfigFile, const char *szKey, long *pDest)
{
    int rc;
    char szValue[64];

    if (!hConfigFile  || !szKey || !pDest)
    {
        //fprintf(stderr, "ERROR: Parameter error\n");
       return 6007;
    }

    rc = my_readSimpleConfigFileStr(hConfigFile, szKey, szValue, sizeof(szValue));
    if (rc)
    {
        return rc;
    }
    *pDest = atol(szValue);
    return 0;
}

void my_closeSimpleConfigFile(FILE *hConfigFile)
{
    if (hConfigFile)
        fclose(hConfigFile);
}

// ================================================================================
//
// ================================================================================


/*---------------------------------------------------------------------------
 * Function:        __Config_ReadEntireFileIntoMemory
 * Description:     Read data on the configure file
 * Parameters:      pData - the buffer to be saved the data
 *                  numByte - the number of byte data to be read
 * Return:          none
 ---------------------------------------------------------------------------*/
static int __Config_ReadEntireFileIntoMemory (const char *szFilename, void *pData, unsigned int bytesToRead)
{
    FILE *       fIn;
    int bytesRead = 0;

    fIn = fopen(szFilename, "rb");
    if (!fIn)
    {
        fprintf(stderr, "ERROR: Error %d opening file \"%s\" for reading\n", errno, szFilename);
        return 6008;
    }

    bytesRead = fread(pData, 1, bytesToRead, fIn);
    if (bytesRead == -1)
    {
        fprintf(stderr, "ERROR: Error %u attempting to read %u bytes from file \"%s\"\n", errno, bytesToRead, szFilename);
        fclose(fIn);
        return 6009;
    }

    fclose(fIn);
    //fprintf(stderr, "INFO: Configuration successfully read from \"%s\" (%d bytes)\n", szFilename, bytesRead );
    return 0;
}


static int __getFileInfo(const char *szFilename, long *pRetFilesize)
{
    int         rc;

    *pRetFilesize = -1;

    if (!szFilename)
    {
        fprintf(stderr, "ERROR: Parameter error\n");
        return 6001;
    }

    rc = my_fileExists(szFilename);
    if (rc == false)
    {
        fprintf(stderr, "ERROR: File not found: %s\n", szFilename);
        return 6004;
    }

    *pRetFilesize = my_getFilesize(szFilename);
    if (*pRetFilesize < 0)
    {
        fprintf(stderr, "ERROR: Unable to determine size of file: %s\n", szFilename);
        return 6005;
    }
    return 0;
}

int my_readEntireConfigFileIntoMemory(const char *szConfigFilename, char **pszConfigFileContents)
{
    long  filesize;
    int   rc;

    *pszConfigFileContents = NULL;

    if (!szConfigFilename)
    {
        fprintf(stderr, "ERROR: Parameter error\n");
        return 6000;
    }

    rc = __getFileInfo(szConfigFilename, &filesize);
    if (rc)
        return rc;
    if (filesize == 0)
    {
        fprintf(stderr, "ERROR: Empty file\n");
        return 6006;
    }

    *pszConfigFileContents = malloc(filesize+1); // We will terminate the json string
    if (*pszConfigFileContents == NULL)
    {
        fprintf(stderr, "ERROR: Out of memory\n");
        return 6007;
    }

    rc = __Config_ReadEntireFileIntoMemory(szConfigFilename, (unsigned char *)(*pszConfigFileContents), (unsigned int)filesize);
    if (rc != 0)
    {
        fprintf(stderr, "ERROR: Read failed\n");
        free(*pszConfigFileContents);
        return rc;
    }

    // Null terminate the json string
    (*pszConfigFileContents)[filesize] = '\0';

    // All is good.
    // The *pszConfigFileContents buffer point to malloc'd memory and ultimately needs to be free'd by the caller.

    return 0;
}

/*
int my_readEntireConfigFileIntoMemoryEnv(const char *szConfigEnvVar, char **pszFilename, char **pszConfigFileContents)
{
    int   rc;

    *pszConfigFileContents = NULL;
    *pszFilename = NULL;

    if (!szConfigEnvVar)
    {
        fprintf(stderr, "ERROR: Parameter error\n");
        return 6000;
    }

    rc = my_getFilenameFromEnvVar(szConfigEnvVar, pszFilename);
    if (rc)
    {
        fprintf(stderr, "ERROR: Cannot find config file from: %s\n", szConfigEnvVar);
        return rc;
    }

    rc = my_readEntireConfigFileIntoMemory(*pszFilename, pszConfigFileContents);
    if (rc)
    {
        return rc;
    }

    // All is good.
    // Both *pszFilename and *pszConfigFileContents buffers point to malloc'd memory and ultimately need to be free'd by the caller.

    return 0;
}
*/
