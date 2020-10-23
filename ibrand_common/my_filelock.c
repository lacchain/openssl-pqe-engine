///////////////////////////////////////////////////////////////////////////////
// Various synchronisation utilities
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
#include "my_logging.h"
#include "my_filelock.h"

static bool __makeLockfileName(char *szLockFilePath, char *szFilename, char *szLockfileName, size_t cbLockfileName, int loglevel)
{
    char szResult[_MAX_PATH];

    if (!szFilename || !szLockfileName || !cbLockfileName)
    {
       if (loglevel & 0x01) fprintf(stderr, "__makeLockfileName Param error...\n");
       if (loglevel & 0x02) app_tracef("__makeLockfileName Param error...\n");
       return false;
    }

    if (szLockFilePath == NULL)
    {
        // Create the file in the same location as szFilename, but with an additional .lock appended
        strcpy(szResult,szFilename);
        strcat(szResult,".lock");
    }
    else
    {
        // Create the file in the szLockFilePath location (e.g. /tmp).
        // The filename is the same as the base name in szFilename, but with an additional .lock appended.
        // If we have any problems, use szFilename with non-alphanumeric chars replaced with '_'
        // For example:
        //      Params "/tmp" and "/var/lib/ibrand/ibrand_data.bin"
        // becomes
        //      /tmp/ibrand_data.bin.lock
        // or
        //      /tmp/_var_lib_ibrand_ibrand_data_bin.lock

        // Try to get the basename of szFilename.
        char szFilenameWithoutPath[_MAX_PATH];
        char *pBasename = basename(szFilename); // basename() returns a pointer to internal static storage
        if (!pBasename || strcmp(pBasename,".")==0 || strcmp(pBasename,PATHSEPARATORSTR)==0 )
        {
            // Replace all non-alphanumeric chars with '_'
            my_strlcpy(szFilenameWithoutPath, szFilename, sizeof(szFilenameWithoutPath));
            for (size_t ii=0; ii<strlen(szFilenameWithoutPath); ii++)
            {
                if (!isalnum(szFilenameWithoutPath[ii]))
                   szFilenameWithoutPath[ii] = '_';
            }
        }
        else
            my_strlcpy(szFilenameWithoutPath, pBasename, sizeof(szFilenameWithoutPath));

        // Build the filename
        strcpy(szResult,szLockFilePath);
        // Add separator (if it doesn't already exist)
        if (szLockFilePath[strlen(szLockFilePath)-1] != PATHSEPARATOR)
            strcat(szResult,PATHSEPARATORSTR);
        strcat(szResult,szFilenameWithoutPath);
        strcat(szResult,".lock");
    }
    if (loglevel & 0x01) fprintf(stderr, "__makeLockfileName(%s)...\n", szResult );
    if (loglevel & 0x02) app_tracef("__makeLockfileName(%s)...\n", szResult );
    my_strlcpy(szLockfileName, szResult, cbLockfileName);
    return true;
}

void my_waitForFileLock(char *szLockFilePath, char *szFilename, int loglevel)
{
    FILE *fLock;
    char szLockFilename[256];
    size_t bytesWritten;

    __makeLockfileName(szLockFilePath, szFilename, szLockFilename, sizeof(szLockFilename), loglevel);

    if (loglevel & 0x01) fprintf(stderr, "WaitForFileLock(%s)...\n", szLockFilename );
    if (loglevel & 0x02) app_tracef("WaitForFileLock(%s)...\n", szLockFilename );
    for(;;)
    {
        if (my_fileExists(szLockFilename))
        {
            if (loglevel & 0x01) fprintf(stderr, "my_fileExists(%s). sleep(3)\n", szLockFilename );
            if (loglevel & 0x02) app_tracef("my_fileExists(%s). sleep(3)\n", szLockFilename );
            sleep(3);
            continue;
        }
        if (loglevel & 0x01) fprintf(stderr, "FileDoesNotExist(%s). Creating...\n", szLockFilename );
        if (loglevel & 0x02) app_tracef("FileDoesNotExist(%s). Creating...\n", szLockFilename );
        fLock = fopen(szLockFilename,"wb");
        if (!fLock)
        {
            if (loglevel & 0x01) fprintf(stderr, "CreateFailed(%s). sleep(3)\n", szLockFilename );
            if (loglevel & 0x02) app_tracef("CreateFailed(%s). sleep(3)\n", szLockFilename );
            sleep(3);
            continue;
        }
        if (loglevel & 0x01) fprintf(stderr, "CreatedOK(%s). Writing...\n", szLockFilename );
        if (loglevel & 0x02) app_tracef("CreatedOK(%s). Writing...\n", szLockFilename );
        bytesWritten = fwrite("X",1,1,fLock);
        if (bytesWritten != 1)
        {
            fclose(fLock);
            if (loglevel & 0x01) fprintf(stderr, "WriteFailed(%s). sleep(3)\n", szLockFilename );
            if (loglevel & 0x02) app_tracef("WriteFailed(%s). sleep(3)\n", szLockFilename );
            sleep(3);
            continue;
        }
        if (loglevel & 0x01) fprintf(stderr, "WriteOk(%s). Closing...\n", szLockFilename );
        if (loglevel & 0x02) app_tracef("WriteOk(%s). Closing...\n", szLockFilename );
        fclose(fLock);
        break;
    }
    if (loglevel & 0x01) fprintf(stderr, "WaitForFileLock(%s). LockedOk\n", szLockFilename );
    if (loglevel & 0x02) app_tracef("WaitForFileLock(%s). LockedOk\n", szLockFilename );
}

void my_releaseFileLock(char *szLockFilePath, char *szFilename, int loglevel)
{
    char szLockFilename[256];

    __makeLockfileName(szLockFilePath, szFilename, szLockFilename, sizeof(szLockFilename), loglevel);

    if (loglevel & 0x01) fprintf(stderr, "ReleaseFileLock(%s)...\n", szLockFilename );
    if (loglevel & 0x02) app_tracef("ReleaseFileLock(%s)...\n", szLockFilename );
    for(;;)
    {
        if (!my_fileExists(szLockFilename))
        {
            if (loglevel & 0x01) fprintf(stderr, "FileDoesNotExist(%s). Returning\n", szLockFilename );
            if (loglevel & 0x02) app_tracef("FileDoesNotExist(%s). Returning\n", szLockFilename );
            return;
        }
        if (loglevel & 0x01) fprintf(stderr, "FileExistsOk(%s). Deleting...\n", szLockFilename );
        if (loglevel & 0x02) app_tracef("FileExistsOk(%s). Deleting...\n", szLockFilename );
        unlink(szLockFilename);
        if (loglevel & 0x01) fprintf(stderr, "DeleteOk(%s). DoubleChecking...\n", szLockFilename );
        if (loglevel & 0x02) app_tracef("DeleteOk(%s). DoubleChecking...\n", szLockFilename );
        if (my_fileExists(szLockFilename))
        {
            if (loglevel & 0x01) fprintf(stderr, "DeleteFailed(%s). sleep(3)\n", szLockFilename );
            if (loglevel & 0x02) app_tracef("DeleteFailed(%s). sleep(3)\n", szLockFilename );
            sleep(3);
            continue;
        }
        if (loglevel & 0x01) fprintf(stderr, "DeleteOk(%s).\n", szLockFilename );
        if (loglevel & 0x02) app_tracef("DeleteOk(%s).\n", szLockFilename );
        break;
    }
    if (loglevel & 0x01) fprintf(stderr, "ReleaseFileLock(%s). UnlockedOk\n", szLockFilename );
    if (loglevel & 0x02) app_tracef("ReleaseFileLock(%s). UnlockedOk\n", szLockFilename );
}
