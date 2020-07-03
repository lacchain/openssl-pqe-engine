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

#ifndef _INCLUDE_MY_FILELOCKLOGGING_H_
#define _INCLUDE_MY_FILELOCKLOGGING_H_

///////////////////////////////////////////////////////////////////////////////
// File Locking Functions
///////////////////////////////////////////////////////////////////////////////
extern void my_waitForFileLock(char *szLockFilePath, char *szFilename, int loglevel);
extern void my_releaseFileLock(char *szLockFilePath, char *szFilename, int loglevel);

#endif // _INCLUDE_MY_FILELOCKLOGGING_H_
