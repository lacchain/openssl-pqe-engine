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

#define NO_EXPECTATION_OF_FILESIZE 0

extern int ReadContentsOfFile(char *szFilename, tLSTRING *pDest, size_t expectedNumberOfBytes);
extern int WriteToFile(char *szFilename, tLSTRING *pSrc, bool mayOverwrite);
extern bool IsHexDigit(unsigned char ch);
extern bool IsHexString(const tLSTRING *pHexData);
extern bool DecodeHexString(const tLSTRING *pHexData, tLSTRING *pBinaryData);
extern char *ExtractSubstring(char *pTokenData, const char *pPrefix, const char *pSuffix);

#endif // _INCLUDE_IBRAND_SERVICE_UTILS_H_
