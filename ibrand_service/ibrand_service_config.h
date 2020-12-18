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

#ifndef _INCLUDE_IBRAND_SERVICE_CONFIG_H_
#define _INCLUDE_IBRAND_SERVICE_CONFIG_H_

#include "../ibrand_common/my_utilslib.h"
#include "ibrand_service_utils.h"

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBSCF_FLOOR 18800
#define ERC_IBSCF_PARAMERR_USERNAME_NOT_SPECIFIED  18810
#define ERC_IBSCF_PARAMERR_USERPSWD_NOT_SPECIFIED  18820
#define ERC_IBSCF_PARAMERR_BASEURL_NOT_SPECIFIED   18830
#define ERC_IBSCF_JSON_PARSE_ERROR                 18840
#define ERC_IBSCF_NOMEM_FOR_JSON                   18850
#define ERC_IBSCF_NOMEM_FOR_OOB                    18860
#define ERC_IBSCF_OOB_JSON_PARSE_ERROR             18870
#define ERC_IBSCF_HEX_DECODE_FAILURE_OF_KEMKEY     18880


#define DBGBIT_STATUS   0
#define DBGBIT_CONFIG   1
#define DBGBIT_PROGRESS 2
#define DBGBIT_AUTH     3
#define DBGBIT_DATA     4
#define DBGBIT_CURL     5
#define DBGBIT_SPARE5   6
#define DBGBIT_SPARE6   7


typedef struct tagIB_CONFIGDATA
{
    // Configuration
    unsigned char  fVerbose;                        // bit 0=general, bit1=config bit2=auth, bit3=data, bit4=curl:
    // Auth
    char          szAuthType[16];                   // "SIMPLE";
    char          szAuthUrl[_MAX_URL];              // "https://ironbridgeapi.com/login";
    char          szUsername[32];
    char          szPassword[32];
    char          szAuthSSLCertFile[_MAX_PATH];     // "/etc/ssl/certs/client_cert.pem"
    char          szAuthSSLCertType[16];            // "PEM"
    char          szAuthSSLKeyFile[_MAX_PATH];      // "/etc/ssl/private/client_key.pem"
    int           authRetryDelay;
    // Connection
    char          szBaseUrl[_MAX_URL];              // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    int           bytesPerRequest;                  // Tested with 16 & 256
    int           retrievalRetryDelay;
    // Storage
    char          szStorageType[16];                // "FILE", "SHMEM"
    char          szStorageDataFormat[16];          // RAW, BASE64, HEX
    char          szStorageFilename[_MAX_PATH];     // "/var/lib/ibrand/ibrand_data.bin"
    char          szStorageLockfilePath[_MAX_PATH]; // "/tmp"
    long          storageHighWaterMark;             // 1038336 // 1MB
    long          storageLowWaterMark;              // 102400  // 100KB
    char          shMemBackingFilename[_MAX_PATH];  // "shmem_ibrand01" // e.g. /dev/shm/shmem_ibrand01
    char          shMemSemaphoreName[16];           // "sem_ibrand01"
    long          shMemStorageSize;                 // (100*1024)
    long          shMemLowWaterMark;                // 102400  // 100KB
    int           idleDelay;                        // seconds, e.g. 2

    size_t        secretKeyBytes;
    size_t        publicKeyBytes;
    // SRNG Config
    unsigned char useSecureRng;
    int           preferredKemAlgorithm;
    char          clientSetupOOBPath[_MAX_PATH];
    char          clientSetupOOB1Filename[_MAX_PATH];
    char          clientSetupOOBNFilename[_MAX_PATH];
    char          ourKemSecretKeyFilename[_MAX_PATH];
    //char          theirSigningPublicKeyFilename[_MAX_PATH];
} tIB_CONFIGDATA;

extern tERRORCODE ValidateSettings(tIB_CONFIGDATA *pIBConfig);
extern tERRORCODE ReadConfig(char *szConfigFilename, tIB_CONFIGDATA *pIBConfig, size_t secretKeyBytes, size_t publicKeyBytes);
extern void PrintConfig(tIB_CONFIGDATA *pIBConfig);
extern tERRORCODE GetBinaryDataFromOOBFile(char *szSrcFilename, tLSTRING *pDestBinaryData);

#endif // _INCLUDE_IBRAND_SERVICE_CONFIG_H_
