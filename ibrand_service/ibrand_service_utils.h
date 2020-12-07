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

#ifndef _INCLUDE_IBRAND_SERVICE_UTILS_H_
#define _INCLUDE_IBRAND_SERVICE_UTILS_H_

#include "../ibrand_common/my_utilslib.h"

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBUTL_FLOOR 19600
#define ERC_IBUTL_PARAMERR_FILENAME_NOT_SPECIFIED 19610
#define ERC_IBUTL_PARAMERR_FILE_NOT_FOUND         19620
#define ERC_IBUTL_PARAMERR_FILE_ALREADY_EXISTS    19630
#define ERC_IBUTL_FILESIZE_ERROR                  19640
#define ERC_IBUTL_NOMEM_FOR_CONTENTS              19650
#define ERC_IBUTL_FILE_OPEN_ERROR                 19660
#define ERC_IBUTL_FILE_READ_ERROR                 19670
#define ERC_IBUTL_FILE_WRITE_ERROR                19680


#define NO_EXPECTATION_OF_FILESIZE 0


extern tERRORCODE ReadContentsOfFile(char *szFilename, tLSTRING *pDest, size_t expectedNumberOfBytes);
extern tERRORCODE WriteToFile(char *szFilename, tLSTRING *pSrc, bool mayOverwrite);
extern bool IsHexDigit(unsigned char ch);
extern bool IsHexString(const tLSTRING *pHexData);
extern bool DecodeHexString(const tLSTRING *pHexData, tLSTRING *pBinaryData);
extern char *ExtractSubstring(char *pTokenData, const char *pPrefix, const char *pSuffix);

#endif // _INCLUDE_IBRAND_SERVICE_UTILS_H_
