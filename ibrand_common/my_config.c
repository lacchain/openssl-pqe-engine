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
        //app_tracef("ERROR: Parameter error\n");
        return 6000;
    }

    szConfigfilePath = getenv(szConfigEnvVar); // Returns a pointer into the current environment
    if (!szConfigfilePath)
    {
        app_tracef("ERROR: Cannot find environment variable: %s\n", szConfigEnvVar);
        return 6001;
    }

    // Effectively, a strdup
    *pszFilename = malloc(strlen(szConfigfilePath));
    if (*pszFilename == NULL)
    {
        app_tracef("ERROR: Out of memory\n");
        return 6002;
    }
    strcpy(*pszFilename, szConfigfilePath);

    return 0;
}

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
        app_tracef("ERROR: Error %d opening file \"%s\" for reading\n", errno, szFilename);
        return 6008;
    }

    bytesRead = fread(pData, 1, bytesToRead, fIn);
    if (bytesRead == -1)
    {
        app_tracef("ERROR: Error %u attempting to read %u bytes from file \"%s\"\n", errno, bytesToRead, szFilename);
        fclose(fIn);
        return 6009;
    }

    fclose(fIn);
    //app_tracef("INFO: Configuration successfully read from \"%s\" (%d bytes)\n", szFilename, bytesRead );
    return 0;
}


static int __getFileInfo(const char *szFilename, long *pRetFilesize)
{
    int         rc;

    *pRetFilesize = -1;

    if (!szFilename)
    {
        app_tracef("ERROR: Parameter error\n");
        return 6001;
    }

    rc = my_fileExists(szFilename);
    if (rc == false)
    {
        app_tracef("ERROR: File not found: %s\n", szFilename);
        return 6004;
    }

    *pRetFilesize = my_getFilesize(szFilename);
    if (*pRetFilesize < 0)
    {
        app_tracef("ERROR: Unable to determine size of file: %s\n", szFilename);
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
        app_tracef("ERROR: Parameter error\n");
        return 6000;
    }

    rc = __getFileInfo(szConfigFilename, &filesize);
    if (rc)
        return rc;
    if (filesize == 0)
    {
        app_tracef("ERROR: Empty file\n");
        return 6006;
    }

    *pszConfigFileContents = malloc(filesize+1); // We will terminate the json string
    if (*pszConfigFileContents == NULL)
    {
        app_tracef("ERROR: Out of memory\n");
        return 6007;
    }

    rc = __Config_ReadEntireFileIntoMemory(szConfigFilename, (unsigned char *)(*pszConfigFileContents), (unsigned int)filesize);
    if (rc != 0)
    {
        app_tracef("ERROR: Read failed\n");
        free(*pszConfigFileContents);
        return rc;
    }

    // Null terminate the json string
    (*pszConfigFileContents)[filesize] = '\0';

    // All is good.
    // The *pszConfigFileContents buffer point to malloc'd memory and ultimately needs to be free'd by the caller.

    return 0;
}
