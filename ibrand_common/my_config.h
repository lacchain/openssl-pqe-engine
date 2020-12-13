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

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_CFG_FLOOR 18000
#define ERC_CFG_PARAMETER_ERROR_CONFIG_ENVVAR         18010
#define ERC_CFG_NOENT_CONFIG_ENVVAR_NOT_FOUND         18020
#define ERC_CFG_NOMEM_CONFIG_FILE_PATH                18030
#define ERC_CFG_FILE_OPEN_FAILED                      18040
#define ERC_CFG_FILE_READ_FAILED                      18050
#define ERC_CFG_PARAM_ERROR_FILENAME_NOT_SPECIFIED    18060
#define ERC_CFG_NOENT_FILE_NOT_FOUND                  18070
#define ERC_CFG_FILE_SIZE_UNKNOWN                     18080
#define ERC_CFG_FILE_IS_EMPTY                         18090
#define ERC_CFG_NOMEM_TO_READ_FILE_CONTENTS           18100


///////////////////////////////////////////////////////////////////////////////
// Config Functions
///////////////////////////////////////////////////////////////////////////////
extern tERRORCODE my_getFilenameFromEnvVar(const char *szConfigEnvVar, char **pszFilename);
extern tERRORCODE my_readEntireConfigFileIntoMemory(const char *szConfigFilename, char **pszConfigFileContents);
extern tERRORCODE my_readEntireConfigFileIntoMemoryEnv(const char *szConfigEnvVar, char **pszFilename, char **pszConfigFileContents);

#endif // _INCLUDE_MY_CONFIG_H_
