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

#ifndef _INCLUDE_MY_CONFIG_H_
#define _INCLUDE_MY_CONFIG_H_


#include "stdio.h"

///////////////////////////////////////////////////////////////////////////////
// Config Functions
///////////////////////////////////////////////////////////////////////////////
extern int  my_getFilenameFromEnvVar    (const char *szConfigEnvVar, char **pszFilename);
extern int  my_openSimpleConfigFile     (char *szFilename, FILE **phConfigFile);
extern int  my_openSimpleConfigFileEnv  (const char *szConfigEnvVar, char **pszFilename, FILE **phConfigFile);
extern int  my_readSimpleConfigFileStr  (FILE *hConfigFile, const char *szKey, char *pDest, size_t cbDest);
extern int  my_readSimpleConfigFileByte (FILE * hConfigFile, const char *szKey, unsigned char *pDest);
extern int  my_readSimpleConfigFileInt  (FILE * hConfigFile, const char *szKey, int *pDest);
extern int  my_readSimpleConfigFileLong (FILE * hConfigFile, const char *szKey, long *pDest);
extern void my_closeSimpleConfigFile    (FILE *hConfigFile);

extern int  my_readEntireConfigFileIntoMemory(const char *szConfigFilename, char **pszConfigFileContents);
extern int  my_readEntireConfigFileIntoMemoryEnv(const char *szConfigEnvVar, char **pszFilename, char **pszConfigFileContents);

#endif // _INCLUDE_MY_CONFIG_H_
