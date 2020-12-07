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

#include "ibrand_service_utils.h"

//-----------------------------------------------------------------------
// ReadContentsOfFile
//-----------------------------------------------------------------------
tERRORCODE ReadContentsOfFile(char *szFilename, tLSTRING *pDest, size_t expectedNumberOfBytes)
{
    if (szFilename == NULL || strlen(szFilename) == 0)
    {
        app_tracef("ERROR: Filename not specified");
        return ERC_IBUTL_PARAMERR_FILENAME_NOT_SPECIFIED;
    }

    if (!my_fileExists(szFilename))
    {
        app_tracef("ERROR: File not found: \"%s\"", szFilename);
        return ERC_IBUTL_PARAMERR_FILE_NOT_FOUND;
    }

    size_t sizeOfFileOnDisk = my_getFilesize(szFilename);
    // If expectedNumberOfBytes is non-zero, then check that filesize is as expected, else, id zero, do not do the check
    if (expectedNumberOfBytes != NO_EXPECTATION_OF_FILESIZE && sizeOfFileOnDisk != expectedNumberOfBytes)
    {
        app_tracef("ERROR: Size of file (%s, %u bytes) is not as expected (%u bytes)", szFilename, sizeOfFileOnDisk, expectedNumberOfBytes);
        return ERC_IBUTL_FILESIZE_ERROR;
    }
    pDest->pData = (char *)malloc(sizeOfFileOnDisk);
    if (!pDest->pData)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for file contents", sizeOfFileOnDisk);
        return ERC_IBUTL_NOMEM_FOR_CONTENTS;
    }

    FILE *fIn = fopen(szFilename, "rb");
    if (!fIn)
    {
        app_tracef("ERROR: Failed to open input file: \"%s\"", szFilename);
        memset(pDest->pData, 0, sizeOfFileOnDisk);
        free(pDest->pData);
        pDest->pData = NULL;
        pDest->cbData = 0;
        return ERC_IBUTL_FILE_OPEN_ERROR;
    }
    size_t bytesRead = fread(pDest->pData, 1, sizeOfFileOnDisk, fIn);
    if (bytesRead != sizeOfFileOnDisk)
    {
        app_tracef("ERROR: Failed to read from file: \"%s\"", szFilename);
        fclose(fIn);
        memset(pDest->pData, 0, sizeOfFileOnDisk);
        free(pDest->pData);
        pDest->pData = NULL;
        pDest->cbData = 0;
        return ERC_IBUTL_FILE_READ_ERROR;
    }
    pDest->cbData = bytesRead;
    fclose(fIn);

    return ERC_OK;
}

//-----------------------------------------------------------------------
// WriteToFile
//-----------------------------------------------------------------------
tERRORCODE WriteToFile(char *szFilename, tLSTRING *pSrc, bool mayOverwrite)
{
    if (szFilename == NULL || strlen(szFilename) == 0)
    {
        app_tracef("ERROR: Cannot write to a file with no name");
        return ERC_IBUTL_PARAMERR_FILENAME_NOT_SPECIFIED;
    }

    if (!mayOverwrite && my_fileExists(szFilename))
    {
        app_tracef("ERROR: File exists and overwrite not permitted: \"%s\"", szFilename);
        return ERC_IBUTL_PARAMERR_FILE_ALREADY_EXISTS;
    }

    FILE *fOut = fopen(szFilename, "wb");
    if (!fOut)
    {
        app_tracef("ERROR: Failed to open output file: \"%s\"", szFilename);
        return ERC_IBUTL_FILE_OPEN_ERROR;
    }
    size_t bytesWritten = fwrite(pSrc->pData, 1, pSrc->cbData, fOut);
    if (bytesWritten != pSrc->cbData)
    {
        app_tracef("ERROR: Failed to write all data to file: \"%s\"", szFilename);
        fclose(fOut);
        return ERC_IBUTL_FILE_WRITE_ERROR;
    }
    fclose(fOut);
    return ERC_OK;
}

bool IsHexDigit(unsigned char ch)
{
    if (ch >= '0' && ch <= '9')
        return true;
    if (ch >= 'A' && ch <= 'F')
        return true;
    if (ch >= 'a' && ch <= 'f')
        return true;
    return false;
}

bool IsHexString(const tLSTRING *pHexData)
{
    size_t numberOfHexChars = pHexData->cbData;

    //if (localDebugTracing) app_tracef("DEBUG: HexString Len   = %u", numberOfHexChars);
    //if (localDebugTracing) app_tracef("DEBUG: HexString START = \"%c%c%c%c...\"", pHexData->pData[0], pHexData->pData[1], pHexData->pData[2], pHexData->pData[3]);
    //if (localDebugTracing) app_tracef("DEBUG: HexString END   = \"...%c%c%c%c\"", pHexData->pData[pHexData->cbData-4], pHexData->pData[pHexData->cbData-3], pHexData->pData[pHexData->cbData-2], pHexData->pData[pHexData->cbData-1]);

    if (numberOfHexChars%2 != 0)
    {
        app_tracef("WARNING: The length of a HexString (%u) must be even", numberOfHexChars);
        return false;
    }

    for (size_t ii = 0; ii < numberOfHexChars; ii++)
    {
        if (!IsHexDigit(pHexData->pData[ii]))
        {
            app_tracef("WARNING: Non-hex digit found at offset %u: '%c'", ii, pHexData->pData[ii]);
            return false;
        }
    }
    return true;
}

bool DecodeHexString(const tLSTRING *pHexData, tLSTRING *pBinaryData)
{
    char *pSrc;
    char *pDest;
    unsigned char val;
    size_t numberOfHexChars = pHexData->cbData;

    if (!IsHexString(pHexData))
    {
        app_tracef("ERROR: Invalid hex string");
        return false;
    }

    pSrc = pHexData->pData;
    pBinaryData->pData = (char *)malloc(numberOfHexChars/2);
    if (!pBinaryData->pData)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for binary string", numberOfHexChars/2);
        return false;
    }
    pBinaryData->cbData = numberOfHexChars/2;

    pDest = pBinaryData->pData;
    for (size_t ii = 0; ii < numberOfHexChars/2; ii++)
    {
        val = 0x55; // Vaguely identifiable uninitialised value
        sscanf(pSrc, "%2hhx", &val);
        pSrc += 2;
        *pDest = val;
        pDest++;
    }

    return true;
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
