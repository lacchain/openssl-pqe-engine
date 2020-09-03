///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// Based on the service template provided by Devin Watson:
// http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html
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

#include <curl/curl.h>
#include <openssl/aes.h>

#include "../PQCrypto-LWEKE/src/api_frodo640.h"

#define SYSTEM_NAME    "FrodoKEM-640"
#define crypto_kem_keypair            crypto_kem_keypair_Frodo640
#define crypto_kem_enc                crypto_kem_enc_Frodo640
#define crypto_kem_dec                crypto_kem_dec_Frodo640

// int crypto_kem_keypair_Frodo640 (unsigned char *pk, unsigned char *sk);
// int crypto_kem_enc_Frodo640     (unsigned char *ct, unsigned char *ss, const unsigned char *pk);
// int crypto_kem_dec_Frodo640     (unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#include "my_utilslib.h"
#include "IB_SymmetricEncryption.h"


#if LIBCURL_VERSION_NUM < 0x070c03
#error "ERROR - Requires libcurl of 7.12.3 or greater"
#endif

#define RUN_AS_DAEMON

#define CONFIG_HARDCODED 1
#define CONFIG_SIMPLE    2
#define CONFIG_JSON      3
#define USE_CONFIG CONFIG_JSON

#define DBGBIT_STATUS  0
#define DBGBIT_CONFIG  1
#define DBGBIT_AUTH    2
#define DBGBIT_DATA    3
#define DBGBIT_CURL    4
#define DBGBIT_SPARE5  5
#define DBGBIT_SPARE6  6
#define DBGBIT_SPARE7  7

//#define FORCE_ALL_LOGGING_ON

#ifdef FORCE_ALL_LOGGING_ON_____EXCEPT_THIS
#define FILELOCK_LOGLEVEL 0x02  // 0x01 is stdout, 0x02 is syslog
#else
#define FILELOCK_LOGLEVEL 0x00  // 0x01 is stdout, 0x02 is syslog
#endif

#define NO_EXPECTATION_OF_FILESIZE 0

typedef struct tagLSTRING
{
    size_t cbData;
    char *pData;
} tLSTRING;

typedef struct tagIB_INSTANCEDATA
{
    // Configuration
    unsigned char  fVerbose;                        // bit 0=general, bit1=config bit2=auth, bit3=data, bit4=curl:
    // Auth
    char          szAuthType[16];                   // "SIMPLE";
    char          szAuthUrl[128];                   // "https://ironbridgeapi.com/login";
    char          szUsername[32];
    char          szPassword[32];
    char          szAuthSSLCertFile[_MAX_PATH];     // "/etc/ssl/certs/client_cert.pem"
    char          szAuthSSLCertType[16];            // "PEM"
    char          szAuthSSLKeyFile[_MAX_PATH];      // "/etc/ssl/private/client_key.pem"
    int           authRetryDelay;
    // Connection
    char          szBaseUrl[128];                   // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    int           bytesPerRequest;                  // Tested with 16 & 256
    int           retrievalRetryDelay;
    // Storage
    char          szStorageType[16];                // "FILE";
    char          szStorageDataFormat[16];          // RAW, BASE64, HEX
    char          szStorageFilename[_MAX_PATH];     // "/var/lib/ibrand/ibrand_data.bin";
    char          szStorageLockfilePath[_MAX_PATH]; // "/tmp";
    long          storageHighWaterMark;             // 1038336; // 1MB
    long          storageLowWaterMark;              // 102400; // 100KB
    int           idleDelay;
    // SRNG Config
    unsigned char useSecureRng;
    char          clientSetupOOBFilename[128];
    char          ourKemSecretKeyFilename[128];
    char          theirSigningPublicKeyFilename[128];

    // State
    char          szConfigFilename[_MAX_PATH];      //  "/usr/local/ssl/ibrand.cnf"
    int           fCurlInitialised;
    int           fAuthenticated;
    int           fRawOutput;
    CURL *        hCurl;
    char *        pRealToken;
    tLSTRING      Token;
    tLSTRING      ResultantData;
    long          code;
    long          response_code;
    long          datastoreFilesize;
    bool          isPaused;

    // SRNG State

    tLSTRING      encryptedKemSecretKey;
    tLSTRING      ourKemSecretKey;
    tLSTRING      theirSigningPublicKey;
    tLSTRING      encapsulatedSessionKey;
    tLSTRING      symmetricSessionKey;

} tIB_INSTANCEDATA;

typedef struct tagIB_OOBDATA
{
    int           requiredSegments;  // "requiredSegments": "1",
    int           segmentNumber;     // "segmentNumber": "1",
    tLSTRING      hexData;           // "hexData": "00112233445566778899AABBCCDDEEFF....",
    tLSTRING      expiryDate;        // "expiryDate": "02/09/2020 18:10:38",
    int           checkSum;          // "checkSum": "39776"
} tIB_OOBDATA;

typedef enum tagSERVICE_STATE
{
    STATE_START = 0,
    STATE_INITIALISECURL,
    STATE_AUTHENTICATE,
    STATE_GETNEWKEMKEYPAIR,
    STATE_DECRYPTKEMSECRETKEY,
    STATE_GETNEWSHAREDSECRET,
    STATE_DECAPSULATESHAREDSECRET,
    STATE_CHECKIFRANDOMNESSISREQUIRED,
    STATE_GETSOMERANDOMNESS,
    STATE_STORERANDOMNESS,
    STATE_DESTROYEXISTINGSHAREDSECRET,
    STATE_SHUTDOWN
} tSERVICESTATE;

typedef enum tagERRORCODE
{
    ERC_AllGood = 0,
    ERC_OopsKemKeyPairExpired = 7010,
    ERC_OopsSharedSecretExpired = 7020,
    ERC_UnspecifiedError = 7999
} tERRORCODE;

#define HTTP_RESP_KEMKEYPAIREXPIRED    (426) // Upgrade Required
#define HTTP_RESP_SHAREDSECRETEXPIRED  (424) // Failed Dependency (WebDAV)

/////////////////////////////////////
// Forward declarations
/////////////////////////////////////
static int DecryptAndStoreKemSecretKey(tIB_INSTANCEDATA *pIBRand);
static int DecapsulateAndStoreSessionKey(tIB_INSTANCEDATA *pIBRand);
static int WriteToFile(char *szFilename, tLSTRING *pSrc, bool mayOverwrite);
static int ImportKemSecretKeyFromClientSetupOOBFile(tIB_INSTANCEDATA *pIBRand);
static bool __ParseJsonOOBData(const char *szJsonString, tIB_OOBDATA *pOobData);

//-----------------------------------------------------------------------
// ReceiveDataHandler_login
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->Token)
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_login(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pNewData;
    size_t     cbNewData;
    tIB_INSTANCEDATA *pIBRand;

    pNewData  = buffer;
    cbNewData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s Login: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbNewData);

    // Free up the old buffer, if there is one
    if (pIBRand->Token.pData && pIBRand->Token.cbData)
    {
        memset(pIBRand->Token.pData, 0, pIBRand->Token.cbData);
        free(pIBRand->Token.pData);
        pIBRand->Token.pData = NULL;
        pIBRand->Token.cbData = 0;
    }

    // Allocate a new buffer
    pIBRand->Token.pData = (char *)malloc(cbNewData);
    if (pIBRand->Token.pData == NULL)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() malloc failure");
        return 0; // Zero bytes processed
    }

    // Copy in the new data
    memcpy(pIBRand->Token.pData, pNewData, cbNewData);
    pIBRand->Token.cbData = cbNewData;

    //app_tracef("INFO: ReceiveDataHandler_login() Saved %lu bytes", pIBRand->Token.cbData);

    // Job done
    return cbNewData;  // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_rng
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->Token)
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_rng(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pNewData;
    size_t     cbNewData;
    char *     pAllData;
    char *     pExistingData;
    size_t     cbExistingData;
    tIB_INSTANCEDATA *pIBRand;

    pNewData  = buffer;
    cbNewData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_rng() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s request: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbNewData);

    pExistingData  = pIBRand->ResultantData.pData;
    cbExistingData = pIBRand->ResultantData.cbData;
    // If pLString already contains some data (i.e. cbExistingData > 0)
    // then we'll...
    //    a) alloc enough room for both
    //    b) copy in the existing data
    //    c) append our new data to it.

    // Allocate a new buffer
    pAllData = (char *)malloc(cbExistingData + cbNewData);
    if (pAllData == NULL)
    {
        app_tracef("ERROR: ReceiveDataHandler_rng() malloc failure");
        return 0; // Zero bytes processed
    }

    // Copy in the existing data, if there is
    if (cbExistingData && pExistingData)
    {
        memcpy(pAllData, pExistingData, cbExistingData);
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: Appending %u bytes", cbNewData);

    // Copy in the new data
    memcpy(pAllData+cbExistingData, pNewData, cbNewData);

    // Point our userp at the new buffer
    pIBRand->ResultantData.pData = pAllData;
    pIBRand->ResultantData.cbData = cbExistingData + cbNewData;

    // Free up the old buffer, if there is one
    if (cbExistingData && pExistingData)
    {
        free(pExistingData);
        pExistingData = NULL;
        cbExistingData = 0;
    }

    //app_tracef("INFO: ReceiveDataHandler_rng() Saved %lu bytes", pIBRand->ResultantData.cbData);

    // Job done
    return cbNewData; // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_RequestNewKeyPair
// This is our CURLOPT_WRITEFUNCTION
// and userp is our encryptedKemSecretKey
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_RequestNewKeyPair(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pInboundEncryptedData;
    size_t     cbInboundEncryptedData;
    tIB_INSTANCEDATA *pIBRand;

    pInboundEncryptedData = buffer;
    cbInboundEncryptedData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_RequestNewKeyPair() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s NewKeyPair: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbInboundEncryptedData);

    // Free up the old buffer, if there is one
    if (pIBRand->encryptedKemSecretKey.pData)
    {
        memset(pIBRand->encryptedKemSecretKey.pData, 0, pIBRand->encryptedKemSecretKey.cbData);
        free(pIBRand->encryptedKemSecretKey.pData);
        pIBRand->encryptedKemSecretKey.pData = NULL;
        pIBRand->encryptedKemSecretKey.cbData = 0;
    }

    // Allocate a new buffer
    pIBRand->encryptedKemSecretKey.pData = (char *)malloc(cbInboundEncryptedData);
    if (pIBRand->encryptedKemSecretKey.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound encrypted data");
        return 0; // Zero bytes processed
    }
    memcpy(pIBRand->encryptedKemSecretKey.pData, pInboundEncryptedData, cbInboundEncryptedData);
    // We will set the size once we know it has completed
    pIBRand->encryptedKemSecretKey.cbData = cbInboundEncryptedData;

    // Destroy any existing KEM secret key, forcing the new one to be decrypted and used as and when needed.
    if (pIBRand->ourKemSecretKey.pData)
    {
        memset(pIBRand->ourKemSecretKey.pData, 0, pIBRand->ourKemSecretKey.cbData);
        free(pIBRand->ourKemSecretKey.pData);
        pIBRand->ourKemSecretKey.pData = NULL;
        pIBRand->ourKemSecretKey.cbData = 0;
    }

    app_tracef("INFO: KEM data stored successfully (%lu bytes)", pIBRand->encryptedKemSecretKey.cbData);

    // Job done
    return cbInboundEncryptedData; // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_SessionKey
// This is our CURLOPT_WRITEFUNCTION
// and userp is our encapsulatedSessionKey
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_SessionKey(char *buffer, size_t size, size_t nmemb, void *userp)
{
    char *     pInboundKemData;
    size_t     cbInboundKemData;
    tIB_INSTANCEDATA *pIBRand;

    pInboundKemData = buffer;
    cbInboundKemData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_SessionKey() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        app_tracef("INFO: %s sessionKey: %u bytes received", pIBRand->useSecureRng?"SRNG":"RNG", cbInboundKemData);

    // Free up the old buffer, if there is one
    if (pIBRand->encapsulatedSessionKey.pData)
    {
        memset(pIBRand->encapsulatedSessionKey.pData, 0, pIBRand->encapsulatedSessionKey.cbData);
        free(pIBRand->encapsulatedSessionKey.pData);
        pIBRand->encapsulatedSessionKey.pData = NULL;
        pIBRand->encapsulatedSessionKey.cbData = 0;
    }

    // Allocate a new buffer
    pIBRand->encapsulatedSessionKey.pData = (char *)malloc(cbInboundKemData);
    if (pIBRand->encapsulatedSessionKey.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound KEM data");
        return 0; // Zero bytes processed
    }
    memcpy(pIBRand->encapsulatedSessionKey.pData, pInboundKemData, cbInboundKemData);
    // We will set the size once we know it has completed
    pIBRand->encapsulatedSessionKey.cbData = cbInboundKemData;

    // Destroy any existing session key, forcing the new one to be decapsulated and used as and when needed.
    if (pIBRand->symmetricSessionKey.pData)
    {
        memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
        free(pIBRand->symmetricSessionKey.pData);
        pIBRand->symmetricSessionKey.pData = NULL;
        pIBRand->symmetricSessionKey.cbData = 0;
    }

    app_tracef("INFO: KEM data stored successfully (%lu bytes)", pIBRand->encapsulatedSessionKey.cbData);

    // Job done
    return cbInboundKemData; // Number of bytes processed
}


//-----------------------------------------------------------------------
// DecryptAndStoreKemSecretKey
//-----------------------------------------------------------------------
static int DecryptAndStoreKemSecretKey(tIB_INSTANCEDATA *pIBRand)
{
    // If there is already a KEM secret key stored, then clear and free it.
    if (pIBRand->ourKemSecretKey.pData)
    {
        memset(pIBRand->ourKemSecretKey.pData, 0, pIBRand->ourKemSecretKey.cbData);
        free(pIBRand->ourKemSecretKey.pData);
        pIBRand->ourKemSecretKey.pData = NULL;
        pIBRand->ourKemSecretKey.cbData = 0;
    }

    // Check that we have the sharedsecret/sessionkey needed for the decryption
    if (!pIBRand->symmetricSessionKey.pData || pIBRand->symmetricSessionKey.cbData <= 0)
    {
        app_tracef("ERROR: Size of sharedsecret is not as expected");
        return 2101;
    }
    // Check that we have the encrypted KEM secret key
    if (!pIBRand->encryptedKemSecretKey.pData || pIBRand->encryptedKemSecretKey.cbData == 0)
    {
        app_tracef("ERROR: Encrypted KEM secret key not found");
        return 2102;
    }

    unsigned char *p = (unsigned char *)pIBRand->encryptedKemSecretKey.pData;
    size_t n = pIBRand->encryptedKemSecretKey.cbData;
    //dumpToFile("/home/jgilmore/dev/dump_KemSecretKey_A_quoted_base64_encrypted_key.txt", p, n);

    //app_trace_hexall("DEBUG: base64 encoded encryptedKemSecretKey:", pIBRand->encryptedKemSecretKey.pData, pIBRand->encryptedKemSecretKey.cbData);
    if (p[0] == '"') {p++; n--;}
    if (p[n-1] == '"') {n--;}
    //app_trace_hexall("DEBUG: p:", p, n);
    //dumpToFile("/home/jgilmore/dev/dump_KemSecretKey_B_base64_encrypted_key.txt", p, n);

    // base64_decode the encapsulate key
    size_t decodeSize = 0;
    unsigned char *rawEncryptedKey = base64_decode((char *)p, n, (size_t *)&(decodeSize));
    if (!rawEncryptedKey)
    {
       app_tracef("WARNING: Failed to decode Base64 EncryptedKey");
       return 2103;
    }
    //dumpToFile("/home/jgilmore/dev/dump_KemSecretKey_C_encrypted_key.txt", rawEncryptedKey, decodeSize);

    if (decodeSize != CRYPTO_CIPHERTEXTBYTES)
    {
        app_tracef("ERROR: Size of decoded encrypted key (%u) is not as expected (%u)", decodeSize, CRYPTO_CIPHERTEXTBYTES);
        //app_trace_hexall("DEBUG: encryptedKemSecretKey:", (char *)rawEncryptedKey, decodeSize);
        return 2104;
    }

    //

    // Do the AES decryption (result returned in a malloc'd buffer, which we will assign to our ourKemSecretKey tLSTRING)
    unsigned char *pDecryptedData = NULL;
    size_t         cbDecryptedData = 0;
    int rc;
    rc = AESDecryptBytes(rawEncryptedKey, decodeSize, (uint8_t *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData, 32 /*saltsize*/, &pDecryptedData, &cbDecryptedData);
    if (rc)
    {
        printf("AESDecryptBytes failed with rc=%d\n", rc);
    }
    pIBRand->ourKemSecretKey.pData = (char *)pDecryptedData;
    pIBRand->ourKemSecretKey.cbData = cbDecryptedData;

    // Persist new KEM secretKey to file
    rc = WriteToFile(pIBRand->ourKemSecretKeyFilename, &(pIBRand->ourKemSecretKey), true);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to save KEM secret key to file \"%s\"", pIBRand->ourKemSecretKeyFilename);
        return rc;
    }

    //dumpToFile("/home/jgilmore/dev/dump_KemSecretKey_D_raw.txt", (unsigned char *)pIBRand->ourKemSecretKey.pData, pIBRand->ourKemSecretKey.cbData);
    app_tracef("INFO: Session key stored successfully (%lu bytes)", pIBRand->ourKemSecretKey.cbData);

    // Job done
    return 0;
}

//-----------------------------------------------------------------------
// DecapsulateAndStoreSessionKey
//-----------------------------------------------------------------------
static int DecapsulateAndStoreSessionKey(tIB_INSTANCEDATA *pIBRand)
{
    // If there is already a session key stored, then clear and free it.
    if (pIBRand->symmetricSessionKey.pData)
    {
        memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
        free(pIBRand->symmetricSessionKey.pData);
        pIBRand->symmetricSessionKey.pData = NULL;
        pIBRand->symmetricSessionKey.cbData = 0;
    }

    // Check that we have the KEM secret key needed for the KEM decapsulation
    if (!pIBRand->ourKemSecretKey.pData || pIBRand->ourKemSecretKey.cbData != CRYPTO_SECRETKEYBYTES)
    {
        app_tracef("ERROR: Size of KEM secret key is not as expected");
        return 2201;
    }
    // Check that we have the encapsulated key
    if (!pIBRand->encapsulatedSessionKey.pData || pIBRand->encapsulatedSessionKey.cbData == 0)
    {
        app_tracef("ERROR: Encapsulated session key not found");
        return 2202;
    }

    unsigned char *p = (unsigned char *)pIBRand->encapsulatedSessionKey.pData;
    size_t n = pIBRand->encapsulatedSessionKey.cbData;
    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_A_quoted_base64_encapsulated_key.txt", p, n);

    //app_trace_hexall("DEBUG: base64 encoded encapsulatedSessionKey:", pIBRand->encapsulatedSessionKey.pData, pIBRand->encapsulatedSessionKey.cbData);
    if (p[0] == '"') {p++; n--;}
    if (p[n-1] == '"') {n--;}
    //app_trace_hexall("DEBUG: p:", p, n);
    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_B_base64_encapsulated_key.txt", p, n);

    // base64_decode the encapsulate key
    size_t decodeSize = 0;
    unsigned char *rawEncapsulatedKey = base64_decode((char *)p, n, (size_t *)&(decodeSize));
    if (!rawEncapsulatedKey)
    {
       app_tracef("WARNING: Failed to decode Base64 EncapsulatedKey");
       return 2203;
    }
    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_C_encapsulated_key.txt", rawEncapsulatedKey, decodeSize);

    if (decodeSize != CRYPTO_CIPHERTEXTBYTES)
    {
        app_tracef("ERROR: Size of decoded encapsulated key (%u) is not as expected (%u)", decodeSize, CRYPTO_CIPHERTEXTBYTES);
        //app_trace_hexall("DEBUG: encapsulatedSessionKey:", (char *)rawEncapsulatedKey, decodeSize);
        return 2204;
    }

    // Allocate a new buffer
    pIBRand->symmetricSessionKey.pData = (char *)malloc(CRYPTO_BYTES);
    if (pIBRand->symmetricSessionKey.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for new session key");
        return 2205;
    }
    // Initialise with something recognisable, so that we can ensure that it has worked
    memset(pIBRand->symmetricSessionKey.pData, 0xAA, CRYPTO_BYTES);

    // Do the KEM decapsulation
    crypto_kem_dec((unsigned char *)pIBRand->symmetricSessionKey.pData, (unsigned char *)rawEncapsulatedKey, (unsigned char *)pIBRand->ourKemSecretKey.pData);

    // We will set the size once we know it has completed
    pIBRand->symmetricSessionKey.cbData = CRYPTO_BYTES;

    //dumpToFile("/home/jgilmore/dev/dump_SessionKey_D_raw.txt", (unsigned char *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData);
    app_tracef("INFO: Session key stored successfully (%lu bytes)", pIBRand->symmetricSessionKey.cbData);

    // Job done
    return 0;
}


//-----------------------------------------------------------------------
// authenticateUser
//-----------------------------------------------------------------------
int authenticateUser(tIB_INSTANCEDATA *pIBRand)
{
    if (!pIBRand)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - instance data is null");
        return 2210;
    }

    if (strlen(pIBRand->szAuthUrl) == 0)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - AuthUrl is empty");
        return 2211;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: authenticateUser: (\"%s\", \"%s\", \"%s\")", pIBRand->szAuthUrl, pIBRand->szUsername, pIBRand->szPassword);
    }
    else
    {
        app_tracef("INFO: Authenticating User: (\"%s\", \"%s\")", pIBRand->szAuthUrl, pIBRand->szUsername);
    }

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pIBRand->szAuthUrl);
//#define USE_CORRECT_ENGINE
#ifdef USE_CORRECT_ENGINE
    // Anything except ourselves.
    // Ideally: RAND_set_rand_engine(NULL)
    //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, "dynamic");
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: Force use of alternate OpenSSL RNG engine");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, "rdrand");
    //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, NULL);
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: CURLOPT_SSLENGINE_DEFAULT");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE_DEFAULT, 1L);
#endif // USE_CORRECT_ENGINE

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
    //    app_tracef("INFO: Construct HTTP Headers");
    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Authorization: Bearer" );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);

    char bodyData[1024] = "";
    if (strcmp(pIBRand->szAuthType, "SIMPLE") == 0)
    {
        sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", pIBRand->szUsername, pIBRand->szPassword );
    }
    else if (strcmp(pIBRand->szAuthType, "CLIENT_CERT") == 0)
    {
        // We don't need nor rely on username and password when using a client certificate,
        // so we'll send just dummy credentials ("a" and "a")
        sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", "a", "a" );
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_POSTFIELDS, bodyData);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_login);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);

    if (strcmp(pIBRand->szAuthType, "CLIENT_CERT") == 0)
    {
#if 0
    INFO: Details of new client: {"clientCertName":"dev.ironbridgeapi.com","clientCertSerialNumber":"00792B31A0DA57D0BD","countryCode":"GB","smsNumber":"07711221555","email":"me@home.com","keyparts":"2","kemAlgorithm":"222"}
    INFO: Sending NewClient request to https://dev.ironbridgeapi.com/api/setupclient
    INFO: Client Setup Successful
    {
      "clientCertName":"dev.ironbridgeapi.com",
      "clientCertSerialNumber":"00792B31A0DA57D0BD",
      "countryCode":"GB",
      "smsNumber":"07711221555",
      "email":"me@home.com",
      "keyparts":"2",
      "kemAlgorithm":"222"
    }
    ironbridge_clientsetup_OOB_70E68FA1690AECE9E223D3ABDD777741.json
#endif

#if 0
* In windows, Open Certificate Manager
* Export cert, with private key to a pfx file e.g. MYDOMAIN.pfx
* openssl pkcs12 -in MYDOMAIN.pfx -clcerts -nokeys -out MYDOMAIN.crt
* openssl x509   -in MYDOMAIN.crt                  -out MYDOMAIN.pem
* openssl pkcs12 -in MYDOMAIN.pfx -nocerts         -out MYDOMAIN-encrypted.key
* openssl rsa    -in MYDOMAIN-encrypted.key        -out MYDOMAIN.key

For example...
echo Create PEM file from PFX file:
openssl pkcs12 -in dev_ironbridgeapi_export_with_pvtkey_aes256sha256.pfx -clcerts -nokeys -out dev_ironbridgeapi_com.crt
openssl x509   -in dev_ironbridgeapi_com.crt                                              -out dev_ironbridgeapi_com.pem

echo Create KEY file from PFX file:
openssl pkcs12 -in dev_ironbridgeapi_export_with_pvtkey_aes256sha256.pfx -nocerts         -out dev_ironbridgeapi_com.key
openssl rsa    -in dev_ironbridgeapi_com.key                                              -out dev_ironbridgeapi_com-decrypted.key
#endif

        // Add the client certificate to our headers
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT, "/etc/ssl/certs/client_cert.pem"); // Load the certificate
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, "PEM");
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY, "/etc/ssl/private/client_key.pem"); // Load the key

        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT, "/etc/ssl/certs/dev_ironbridgeapi_com.pem"); // Load the certificate
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, "PEM");
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY, "/etc/ssl/private/dev_ironbridgeapi_com-decrypted_key.pem"); // Load the key

        // Client Certificate
        app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->szAuthSSLCertFile, pIBRand->szAuthSSLCertType);
        if (!my_fileExists(pIBRand->szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->szAuthSSLCertFile);
            //return 55581;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->szAuthSSLCertType); // Load the certificate type

        // SSL Key
        app_tracef("INFO: Using Client SSL key \"%s\"", pIBRand->szAuthSSLKeyFile);
        if (!my_fileExists(pIBRand->szAuthSSLKeyFile))
        {
            app_tracef("WARNING: Client SSL key file not found: \"%s\"", pIBRand->szAuthSSLKeyFile);
            //return 55582;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY     , pIBRand->szAuthSSLKeyFile ); // Load the key

    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: Connecting to \"%s\" with \"%s\"", pIBRand->szAuthUrl, bodyData);
    }

    /* Do it */
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s Sending \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->szAuthUrl );
    }
    CURLcode      curlResultCodeA;
    curlResultCodeA = curl_easy_perform(pIBRand->hCurl);
    if (curlResultCodeA != CURLE_OK)
    {
      app_tracef("ERROR: authenticateUser failed: rc=%d \"%s\"", curlResultCodeA, curl_easy_strerror(curlResultCodeA));
      return 2212;
    }

    pIBRand->code = 0;
    CURLcode curlResultCodeB;
    curlResultCodeB = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_HTTP_CONNECTCODE, &pIBRand->code);
    if (!curlResultCodeB && pIBRand->code)
    {
        app_tracef("ERROR: authenticateUser: ResultCode=%03ld \"%s\"", pIBRand->code, curl_easy_strerror(pIBRand->code));
        return 2220;
    }

    pIBRand->response_code = 0;
    CURLcode  curlResultCodeC;
    curlResultCodeC = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &pIBRand->response_code);
    if (!curlResultCodeC && (pIBRand->response_code != 200))
    {
        app_tracef("ERROR: authenticateUser: HTTP Responcse Code=%ld", pIBRand->response_code);
        return 2221;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: authenticateUser() Token = [%s]"            , pIBRand->Token.pData);
    }

    curl_slist_free_all(headers); /* free custom header list */
    app_tracef("INFO: Authentication successful: (\"%s\", \"%s\")", pIBRand->szAuthUrl, pIBRand->szUsername);
    return 0;
}

//-----------------------------------------------------------------------
// getRandomBytes
//-----------------------------------------------------------------------
int getRandomBytes(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char * szEndpoint;
    #define MAXUINT_DIGITS 20 // 0x7FFF FFFF FFFF FFFF = 9,223,372,036,854,775,807 ==> 19 digits for signed, 20 for unsigned.

    if (pIBRand->useSecureRng)
    {
        szEndpoint = "srng";
    }
    else
    {
        szEndpoint = "rng";
    }

    pUrl = (char *)malloc(strlen(pIBRand->szBaseUrl)+strlen(szEndpoint)+2+MAXUINT_DIGITS); // i.e. strlen("/rng/NNNNNNN")
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 22230;
    }
    sprintf(pUrl,"%s/%s/%u", pIBRand->szBaseUrl, szEndpoint, pIBRand->bytesPerRequest);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    char *pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
    if (!pAuthHeader)
    {
        app_tracef("ERROR: Out of memory allocating for AuthHeader");
        return 2231;
    }
    sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: %s AuthHeader = \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pAuthHeader);
    }

    headers = curl_slist_append ( headers, pAuthHeader );

    // e.g.
    //   "name": "accept",
    //   "value": "application/json, text/plain, */*"
    //   "name": "authorization",
    //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
    //   "name": "content-type",
    //   "value": "application/json"

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_rng);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    // Do it
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s Sending \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pUrl );
    }
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s response code = %ld", pIBRand->useSecureRng?"SRNG":"RNG", httpResponseCode);
    }
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: %s perform failed: [%s]", pIBRand->useSecureRng?"SRNG":"RNG", curl_easy_strerror(curlResultCode));
        return 2232;
    }

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    curl_slist_free_all(headers); /* free custom header list */
    free(pAuthHeader);
    free(pUrl);

    if (httpResponseCode == HTTP_RESP_SHAREDSECRETEXPIRED)
    {
        return ERC_OopsSharedSecretExpired;
    }
    return 0;
}

//-----------------------------------------------------------------------
// getSecureRNGSessionKey
//-----------------------------------------------------------------------
int getNewKemKeyPair(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char *szEndpoint = "reqkeypair";

    pUrl = (char *)malloc(strlen(pIBRand->szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->szBaseUrl, szEndpoint);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    char *pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
    if (!pAuthHeader)
    {
        app_tracef("ERROR: Out of memory allocating for AuthHeader");
        free(pUrl);
        return 2241;
    }
    sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: %s AuthHeader = \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pAuthHeader);
    }

    headers = curl_slist_append ( headers, pAuthHeader );

    // e.g.
    //   "name": "accept",
    //   "value": "application/json, text/plain, */*"
    //   "name": "authorization",
    //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
    //   "name": "content-type",
    //   "value": "application/json"

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_RequestNewKeyPair);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);


    // Do it
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s Sending \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pUrl );
    }
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s response code = %ld", pIBRand->useSecureRng?"SRNG":"RNG", httpResponseCode);
    }
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: %s perform failed: [%s]", pIBRand->useSecureRng?"SRNG":"RNG", curl_easy_strerror(curlResultCode));
        curl_slist_free_all(headers); /* free custom header list */
        free(pAuthHeader);
        free(pUrl);
        return 2242;
    }

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    if (httpResponseCode == HTTP_RESP_SHAREDSECRETEXPIRED)
    {
        curl_slist_free_all(headers); /* free custom header list */
        free(pAuthHeader);
        free(pUrl);
        return ERC_OopsSharedSecretExpired;
    }

    curl_slist_free_all(headers); /* free custom header list */
    free(pAuthHeader);
    free(pUrl);
    return 0;
}


//-----------------------------------------------------------------------
// getSecureRNGSessionKey
//-----------------------------------------------------------------------
int getSecureRNGSessionKey(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char *szEndpoint = "sharedsecret";

    pUrl = (char *)malloc(strlen(pIBRand->szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->szBaseUrl, szEndpoint);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    char *pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
    if (!pAuthHeader)
    {
        app_tracef("ERROR: Out of memory allocating for AuthHeader");
        free(pUrl);
        return 2241;
    }
    sprintf(pAuthHeader, "authorization: Bearer %s", pIBRand->pRealToken);

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: %s AuthHeader = \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pAuthHeader);
    }

    headers = curl_slist_append ( headers, pAuthHeader );

    // e.g.
    //   "name": "accept",
    //   "value": "application/json, text/plain, */*"
    //   "name": "authorization",
    //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
    //   "name": "content-type",
    //   "value": "application/json"

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_SessionKey);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);


    // Do it
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s Sending \"%s\"", pIBRand->useSecureRng?"SRNG":"RNG", pUrl );
    }
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s response code = %ld", pIBRand->useSecureRng?"SRNG":"RNG", httpResponseCode);
    }
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: %s perform failed: [%s]", pIBRand->useSecureRng?"SRNG":"RNG", curl_easy_strerror(curlResultCode));
        curl_slist_free_all(headers); /* free custom header list */
        free(pAuthHeader);
        free(pUrl);
        return 2242;
    }

    //if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    if (httpResponseCode == HTTP_RESP_KEMKEYPAIREXPIRED)
    {
        curl_slist_free_all(headers); /* free custom header list */
        free(pAuthHeader);
        free(pUrl);
        return ERC_OopsKemKeyPairExpired;
    }

    curl_slist_free_all(headers); /* free custom header list */
    free(pAuthHeader);
    free(pUrl);
    return 0;
}


//-----------------------------------------------------------------------
// storeRandomBytes
//-----------------------------------------------------------------------
void storeRandomBytes(tIB_INSTANCEDATA *pIBRand)
{
    if (pIBRand->ResultantData.pData == NULL || pIBRand->ResultantData.cbData == 0)
    {
        // Nothing to do
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: Nothing to do. [pData=%p, cbData=%u]", pIBRand->ResultantData.pData, pIBRand->ResultantData.cbData);
        }
        return;
    }

    if (pIBRand->useSecureRng)
    {
        // The data is currently Base64 encoded encrypted data
        ///////////////////////////////////
        // DeBase64 the data...
        ///////////////////////////////////
        char * pOriginalData  = pIBRand->ResultantData.pData;
        size_t cbOriginalData = pIBRand->ResultantData.cbData;

        //dumpToFile("/home/jgilmore/dev/dump_SRNG_A_quoted_base64_encrypted_data.txt", (unsigned char *)pIBRand->ResultantData.pData, pIBRand->ResultantData.cbData);

        char * pDecodeData = pOriginalData;
        size_t cbDecodeData = cbOriginalData;
        if (pOriginalData[0] == '"' && pOriginalData[cbOriginalData-1] == '"')
        {
            pDecodeData = pOriginalData + 1;
            cbDecodeData = cbOriginalData - 2;
        }
        else
        {
            pDecodeData = pOriginalData;
            cbDecodeData = cbOriginalData;
        }
        //dumpToFile("/home/jgilmore/dev/dump_SRNG_B_base64_encrypted_data.txt", (unsigned char *)pDecodeData, cbDecodeData);
        size_t cbEncryptedData = 0;
        unsigned char *pEncryptedData = base64_decode(pDecodeData, cbDecodeData, &cbEncryptedData);
        if (!pEncryptedData)
        {
           app_tracef("WARNING: Failed to decode Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
           return;
        }
        free(pIBRand->ResultantData.pData);
        pIBRand->ResultantData.pData = NULL;
        pIBRand->ResultantData.cbData = 0;

        //dumpToFile("/home/jgilmore/dev/dump_SRNG_C_encrypted_data.txt", pEncryptedData, cbEncryptedData);
        ///////////////////////////////////
        // Decrypt the data...
        ///////////////////////////////////

        if (pIBRand->symmetricSessionKey.pData==NULL)
        {
            // Now that we are running in a state machine, this should not be needed - BEGIN
            if (pIBRand->encapsulatedSessionKey.pData==NULL)
            {
                // No keys found
                app_tracef("ERROR: No session key available to decryption SRNG response");
                return; // todo cleanup
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                app_tracef("INFO: Decapsulating session key");
            int rc = DecapsulateAndStoreSessionKey(pIBRand);
            if (rc != 0)
            {
                app_tracef("ERROR: KEM decapsulation failed with rc=%d", rc);
                return; // todo cleanup
            }
            // Now that we are running in a state machine, this should not be needed - END
            // But still need to capture it's absence, Justin Case.
        }

#define USE_PBKDF2
#ifdef USE_PBKDF2
        unsigned char *pDecryptedData = NULL;
        size_t         cbDecryptedData = 0;
        int rc;

        rc = AESDecryptBytes(pEncryptedData, cbEncryptedData, (uint8_t *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData, 32, &pDecryptedData, &cbDecryptedData);
        if (rc)
        {
            printf("AESDecryptBytes failed with rc=%d\n", rc);
        }
        pIBRand->ResultantData.pData = (char *)pDecryptedData;
        pIBRand->ResultantData.cbData = cbDecryptedData;
#else
        // Initialisation vector
        unsigned char iv[AES_BLOCK_SIZE];
        AES_KEY dec_key;

        // AES-128 bit CBC Decryption
        memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly

        // Rfc2898DeriveBytes
        // Crypto::Rfc2898DeriveBytes   derivedBytes(key, saltSize);
        // auto                         salt       = derivedBytes.salt();
        // auto                         keyBytes   = derivedBytes.getBytes(32);
        // auto                         ivBytes    = derivedBytes.getBytes(16);

        // We have a key
        // We have an IV
        // We have some data
        // Let's do it.

        AES_set_decrypt_key((unsigned char *)pIBRand->symmetricSessionKey.pData, pIBRand->symmetricSessionKey.cbData*8, &dec_key); // Size of key is in bits
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
            app_tracef("INFO: Decrypting %u bytes", pIBRand->symmetricSessionKey.cbData);
        unsigned char *pRawData = (unsigned char *)malloc(cbEncryptedData);
        if (!pRawData)
        {
            app_tracef("ERROR: Malloc for decrypted data failed");
            return; // todo cleanup
        }
        AES_cbc_encrypt(pEncryptedData, pRawData, cbEncryptedData, &dec_key, iv, AES_DECRYPT);
        size_t cbRawData = cbEncryptedData;

        free(pEncryptedData);
        pEncryptedData = NULL;
        cbEncryptedData = 0;

        pIBRand->ResultantData.pData = (char *)pRawData;
        pIBRand->ResultantData.cbData = cbRawData;
#endif
        //dumpToFile("/home/jgilmore/dev/dump_SRNG_D_raw_data.txt", (uint8_t *)pIBRand->ResultantData.pData, (size_t)pIBRand->ResultantData.cbData);

        // The data is now raw data
        if (strcmp(pIBRand->szStorageDataFormat,"RAW")!=0)
        {
            app_tracef("WARNING: Only RAW format is supported for SRNG. Discarding %u bytes.", pIBRand->ResultantData.cbData);
            return; // todo cleanup
        }
    }
    else // RNG
    {
        // The data is currently Base64 encoded raw data

        // Format the output data
        if (strcmp(pIBRand->szStorageDataFormat,"RAW")==0)
        {
            // Curl_base64_decode() - Given a base64 string at src, decode it and return
            // an allocated memory in the *outptr. Returns the length of the decoded data.
            //*pcbData = Curl_base64_decode(p, (unsigned char **)ppData)
            // *ppData will, and must, be freed by the caller

            //dumpToFile("/home/jgilmore/dev/dump_Data_A_base64_encrypted_data.txt", p, n);

            //app_tracef("INFO: %s ResultantData[%u] = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
            char * pOriginalData  = pIBRand->ResultantData.pData;
            size_t cbOriginalData = pIBRand->ResultantData.cbData;

            char * pDecodeData = pOriginalData;
            size_t cbDecodeData = cbOriginalData;
            if (pOriginalData[0] == '"' && pOriginalData[cbOriginalData-1] == '"')
            {
                pDecodeData = pOriginalData + 1;
                cbDecodeData = cbOriginalData - 2;
            }
            else
            {
                pDecodeData = pOriginalData;
                cbDecodeData = cbOriginalData;
            }

            // Debugging Begin
            {
                //char *p = pDecodeData;
                //size_t n = cbDecodeData;
                //dumpToFile("/home/jgilmore/dev/dump_Data_A_base64_encrypted_data.txt", (unsigned char *)p, n);
                //app_trace_hexall("DEBUG: base64 encoded data:", p, n);
            }
            // Debugging End

            pIBRand->ResultantData.pData = (char *)base64_decode(pDecodeData, cbDecodeData, (size_t *)&(pIBRand->ResultantData.cbData));
            if (!pIBRand->ResultantData.pData)
            {
               app_tracef("WARNING: Failed to decode Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
               return;
            }
            free(pOriginalData);
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
            {
                app_tracef("INFO: %s ResultantData[%u]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData);
                //app_tracef("INFO: %s ResultantData[%u] = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
            }
        }
        else if (strcmp(pIBRand->szStorageDataFormat,"BASE64")==0)
        {
            // Nothing to do. The data is already Base64 encoded

            // The data may be wrapped in double-quotes, which will need removing
            char * pOriginalData  = pIBRand->ResultantData.pData;
            size_t cbOriginalData = pIBRand->ResultantData.cbData;

            if (pOriginalData[0] == '"' && pOriginalData[cbOriginalData-1] == '"')
            {
                // Alloc a new, smaller buffer, copy the data in, and free up the original buffer.
                // Not the most efficient, but simple - for now.
                pIBRand->ResultantData.cbData = cbOriginalData - 2;
                pIBRand->ResultantData.pData = malloc(pIBRand->ResultantData.cbData);
                if (!pIBRand->ResultantData.pData)
                {
                    app_tracef("WARNING: Failed to clean Base64 data. Discarding %u bytes.", pIBRand->ResultantData.cbData);
                    pIBRand->ResultantData.pData = pOriginalData;
                    pIBRand->ResultantData.cbData = cbOriginalData;
                    return;
                }
                memcpy(pIBRand->ResultantData.pData, pOriginalData+1, pIBRand->ResultantData.cbData);
                free(pOriginalData);
            }
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
            {
                app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
            }
        }
        else if (strcmp(pIBRand->szStorageDataFormat,"HEX")==0)
        {
            // TODO
            app_tracef("WARNING: Storage data format \"%s\"  not yet implemented. Discarding %u bytes.", pIBRand->szStorageDataFormat, pIBRand->ResultantData.cbData);
            return;
        }
        else
        {
            app_tracef("WARNING: Unsupported storage data format \"%s\". Discarding %u bytes.", pIBRand->szStorageDataFormat, pIBRand->ResultantData.cbData);
            return;
        }
    } // RNG


    if (strcmp(pIBRand->szStorageType,"FILE")==0)
    {
        //fprintf(stdout, "%u:%s\n", pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
        FILE *f;
        unsigned int bytesWritten1 = 0;
        unsigned int bytesWritten2 = 0;

        my_waitForFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
        f = fopen(pIBRand->szStorageFilename,"ab");
        if (!f)
        {
            app_tracef("WARNING: Unable to open storage file. Discarding %u bytes.", pIBRand->ResultantData.cbData);
            my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
            // ...and sleep a little in the hope that it will recover
            sleep(1);
            return;
        }
        bytesWritten1 = fwrite(pIBRand->ResultantData.pData, 1, pIBRand->ResultantData.cbData, f);
        if (bytesWritten1 != pIBRand->ResultantData.cbData)
        {
            app_tracef("WARNING: Unable to write all bytes (%d/%d)", bytesWritten1, pIBRand->ResultantData.cbData);
        }
        // Delimit each Base64 block with a LF
        if (strcmp(pIBRand->szStorageDataFormat,"BASE64")==0)
        {
            bytesWritten2 = fwrite("\n", 1, 1, f);
            if (bytesWritten2 != 1)
            {
                app_tracef("WARNING: Unable to write LF");
            }
        }
        fclose(f);
        my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: %s %u+%u bytes stored", pIBRand->useSecureRng?"SRNG":"RNG", bytesWritten1, bytesWritten2);
        }
    }
    else
    {
        app_tracef("WARNING: Unsupported storage type \"%s\". Discarding %u bytes.", pIBRand->szStorageType, pIBRand->ResultantData.cbData);
        return;
    }
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

//-----------------------------------------------------------------------
// validateSettings
//-----------------------------------------------------------------------
int validateSettings(tIB_INSTANCEDATA *pIBRand)
{
    if (strlen(pIBRand->szUsername) == 0)
    {
        app_tracef("ERROR: Username is mandatory, but not supplied. Aborting.");
        return 2250;
    }
    if (strlen(pIBRand->szPassword) == 0)
    {
        app_tracef("ERROR: Password is mandatory, but not supplied. Aborting.");
        return 2251;
    }
    if (strlen(pIBRand->szBaseUrl) == 0)
    {
        // Parameter error
        app_tracef("ERROR: URL is mandatory, but not supplied. Aborting.");
        return 2252;
    }
    return 0;
}

//-----------------------------------------------------------------------
// InitialiseCurl
//-----------------------------------------------------------------------
int InitialiseCurl(tIB_INSTANCEDATA *pIBRand)
{
    //////////////////////////////
    // Initialise libcurl
    //////////////////////////////
    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    pIBRand->hCurl = curl_easy_init();
    if (!pIBRand->hCurl)
    {
      app_tracef("ERROR: Library initialisation failed");
      return 2260;
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
    {
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_TIMEOUT, xxx);
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);


        // CURLOPT_STDERR must be set to something specific.
        // Setting curl_setopt($c, CURLOPT_STDERR, fopen('/curl.txt', 'w+')); fixed my issue.
        // As it turns out curl_setopt($c, CURLOPT_VERBOSE, 1); is not printing the output to STDERR for some reason which I have not uncovered. I did not find the output in any of my PHP, Apache, nor Event Viewer logs.
        // After setting curl_setopt($c, CURLOPT_STDERR, fopen('/curl.txt', 'w+'));, I was able to see the output in the curl.txt file.
        // I am not sure if this is specific to Windows environments.
        //curl_easy_setopt(pIBRand->hCurl, CURLOPT_STDERR, fopen('/curl.txt', 'w+'));

        curl_easy_setopt(pIBRand->hCurl, CURLOPT_VERBOSE, 1L);
        /*
            typedef enum
            {
              CURLINFO_TEXT = 0,
              CURLINFO_HEADER_IN,    // 1
              CURLINFO_HEADER_OUT,   // 2
              CURLINFO_DATA_IN,      // 3
              CURLINFO_DATA_OUT,     // 4
              CURLINFO_SSL_DATA_IN,  // 5
              CURLINFO_SSL_DATA_OUT, // 6
              CURLINFO_END
            } tCURL_INFOTYPE;

            int CurlDebugCallback(CURL *handle, tCURL_INFOTYPE type, char *data, size_t size, void *userptr)
            {
            }
            CURLcode curl_easy_setopt(pIBRand->hCurl, CURLOPT_DEBUGFUNCTION, CurlDebugCallback);
            CURLcode curl_easy_setopt(pIBRand->hCurl, CURLOPT_DEBUGDATA, pIBRand); // JG: Does this call exist - i.e. does CURLOPT_DEBUGFUNCTION have userdata?
        */
    }

    pIBRand->fCurlInitialised = TRUE;
    return 0;
}

//-----------------------------------------------------------------------
// DoAuthentication
//-----------------------------------------------------------------------
int DoSimpleAuthentication(tIB_INSTANCEDATA *pIBRand)
{
    int rc;

    //////////////////////////////
    // Authenticate the user
    //////////////////////////////
    pIBRand->Token.pData = NULL;
    pIBRand->Token.cbData = 0;
    rc = authenticateUser ( pIBRand );
    if (rc != 0)
    {
      app_tracef("ERROR: authenticateUser failed rc=%d", rc);
      return rc; // 2200..2299
    }

    // TokenData is something of the form (without the EOLs)...
    // {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTc1MzgzOTI5LCJleHAiOjE1NzU0NzAzMjksImlhdCI6MTU3NTM4MzkyOSwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.DvrJew9dLYVgmzB36N8LgRT1zT4hJsDtr0pjG_8WJBs",
    //  "notBefore":"2019-12-03T14:38:49.10979Z",
    //  "notAfter":"2019-12-04T14:38:49.10979Z"}

    // Todo: Use strtok or regex or similar
    pIBRand->pRealToken = ExtractSubstring(pIBRand->Token.pData, "\"token\":\"", "\"");
    if (!pIBRand->pRealToken)
    {
        // Check with space after colon
        pIBRand->pRealToken = ExtractSubstring(pIBRand->Token.pData, "\"token\": \"", "\"");
        if (!pIBRand->pRealToken)
        {
          app_tracef("ERROR: Cannot find token in TokenData pData=[%s]", pIBRand->Token.pData);
          return 2270;
        }
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: pRealToken = [%s]", pIBRand->pRealToken);
    }

    //fprintf(stderr, "DEBUG: Token.pData=[%s]\n", pIBRand->Token.pData);
    //fprintf(stderr, "DEBUG: pRealToken=[%s]\n", pIBRand->pRealToken);

    pIBRand->fAuthenticated = TRUE;
    return 0;
}

int DoAuthentication(tIB_INSTANCEDATA *pIBRand)
{
    int rc;

    if (strcmp(pIBRand->szAuthType, "NONE") == 0)
    {
        // Nothing to do
        rc = 0;
    }
    if (strcmp(pIBRand->szAuthType, "SIMPLE") == 0)
    {
        rc = DoSimpleAuthentication(pIBRand);
        if (rc != 0)
        {
            app_tracef("ERROR: Simple authentication failed rc=%d", rc);
            return rc;
        }
    }
    else if (strcmp(pIBRand->szAuthType, "CLIENT_CERT") == 0)
    {
        // Deeper in, the AuthenticateUser function differs for SIMPLE vs. CLIENT_CERT
        rc = DoSimpleAuthentication(pIBRand);
        if (rc != 0)
        {
            app_tracef("ERROR: Simple authentication failed rc=%d", rc);
            return rc;
        }

        //rc = VerifyClientCertificate(pIBRand);
        // if (rc != 0)
        //{
        //    app_tracef("ERROR: Simple authentication failed rc=%d", rc);
        //    return rc;
        //}
    }
    else
    {
        rc = 999; // Unsupported AuthType
        app_tracef("ERROR: Unsupported AuthType rc=%d", rc);
    }

    return rc;
}

//-----------------------------------------------------------------------
// ironbridge_api_finalise
//-----------------------------------------------------------------------
void ironbridge_api_finalise(tIB_INSTANCEDATA *pIBRand)
{
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: ironbridge_api_finalise()");

    //////////////////////////////
    // Cleanup and wipe away our footprints
    //////////////////////////////
    if (pIBRand->pRealToken)
    {
        memset(pIBRand->pRealToken, 0, strlen(pIBRand->pRealToken));
        free(pIBRand->pRealToken);
        pIBRand->pRealToken = NULL;
    }
    if (pIBRand->ResultantData.pData)
    {
        memset(pIBRand->ResultantData.pData, 0, pIBRand->ResultantData.cbData);
        free(pIBRand->ResultantData.pData);
        pIBRand->ResultantData.cbData = 0;
        pIBRand->ResultantData.pData = NULL;
    }
    if (pIBRand->Token.pData)
    {
        memset(pIBRand->Token.pData, 0, pIBRand->Token.cbData);
        free(pIBRand->Token.pData);
        pIBRand->Token.cbData = 0;
        pIBRand->Token.pData = NULL;
    }
    if (pIBRand->symmetricSessionKey.pData)
    {
        memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
        free(pIBRand->symmetricSessionKey.pData);
        pIBRand->symmetricSessionKey.cbData = 0;
        pIBRand->symmetricSessionKey.pData = NULL;
    }
    if (pIBRand->ourKemSecretKey.pData)
    {
        memset(pIBRand->ourKemSecretKey.pData, 0, pIBRand->ourKemSecretKey.cbData);
        free(pIBRand->ourKemSecretKey.pData);
        pIBRand->ourKemSecretKey.cbData = 0;
        pIBRand->ourKemSecretKey.pData = NULL;
    }
    if (pIBRand->theirSigningPublicKey.pData)
    {
        memset(pIBRand->theirSigningPublicKey.pData, 0, pIBRand->theirSigningPublicKey.cbData);
        free(pIBRand->theirSigningPublicKey.pData);
        pIBRand->theirSigningPublicKey.cbData = 0;
        pIBRand->theirSigningPublicKey.pData = NULL;
    }
    curl_easy_cleanup(pIBRand->hCurl);
    curl_global_cleanup();

    if (pIBRand)
    {
        // Destory contents and free
        memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));
        free(pIBRand);
    }
}

//-----------------------------------------------------------------------
// ReadContentsOfFile
//-----------------------------------------------------------------------
static int ReadContentsOfFile(char *szFilename, tLSTRING *pDest, size_t expectedNumberOfBytes)
{
    if (szFilename == NULL || strlen(szFilename) == 0)
    {
        app_tracef("ERROR: Cannot read the contents of a file with no name");
        return 2280;
    }

    if (!my_fileExists(szFilename))
    {
        app_tracef("ERROR: File not found: \"%s\"", szFilename);
        return 2281;
    }

    size_t sizeOfFileOnDisk = my_getFilesize(szFilename);
    // If expectedNumberOfBytes is non-zero, then check that filesize is as expected, else, id zero, do not do the check
    if (expectedNumberOfBytes != NO_EXPECTATION_OF_FILESIZE && sizeOfFileOnDisk != expectedNumberOfBytes)
    {
        app_tracef("ERROR: Size of file (%s, %u bytes) is not as expected (%u bytes)", szFilename, sizeOfFileOnDisk, expectedNumberOfBytes);
        return 2282;
    }
    pDest->pData = malloc(sizeOfFileOnDisk);
    if (!pDest->pData)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for file contents", sizeOfFileOnDisk);
        return 2283;
    }

    FILE *fIn = fopen(szFilename, "rb");
    if (!fIn)
    {
        app_tracef("ERROR: Failed to open input file: \"%s\"", szFilename);
        memset(pDest->pData, 0, sizeOfFileOnDisk);
        free(pDest->pData);
        pDest->pData = NULL;
        pDest->cbData = 0;
        return 2284;
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
        return 2285;
    }
    pDest->cbData = bytesRead;
    fclose(fIn);

    return 0;
}

//-----------------------------------------------------------------------
// WriteToFile
//-----------------------------------------------------------------------
static int WriteToFile(char *szFilename, tLSTRING *pSrc, bool mayOverwrite)
{
    if (szFilename == NULL || strlen(szFilename) == 0)
    {
        app_tracef("ERROR: Cannot write to a file with no name");
        return 2290;
    }

    if (!mayOverwrite && my_fileExists(szFilename))
    {
        app_tracef("ERROR: File exists and overwrite not permitted: \"%s\"", szFilename);
        return 2291;
    }

    FILE *fOut = fopen(szFilename, "wb");
    if (!fOut)
    {
        app_tracef("ERROR: Failed to open output file: \"%s\"", szFilename);
        return 2294;
    }
    size_t bytesWritten = fwrite(pSrc->pData, 1, pSrc->cbData, fOut);
    if (bytesWritten != pSrc->cbData)
    {
        app_tracef("ERROR: Failed to write all data to file: \"%s\"", szFilename);
        fclose(fOut);
        return 2295;
    }
    fclose(fOut);
    return 0;
}

#if (USE_CONFIG==CONFIG_HARDCODED)
static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    int rc;
    if (!pIBRand)
    {
        return 2290;
    }

    UNUSED_PARAM(szConfigFilename);

    app_tracef("WARNING: Configuration from hardcode values");

    //////////////////////////////////////
    // Hardcoded values for testing
    /////////////////////////////////////
    strcpy(pIBRand->szAuthType            , "SIMPLE");
    strcpy(pIBRand->szAuthUrl             , "ironbridgeapi.com/api/login");
    strcpy(pIBRand->szUsername            , "Fred");
    strcpy(pIBRand->szPassword            , "Pa55w0rd");
    strcpy(pIBRand->szAuthSSLCertFile     , "/etc/ssl/certs/client_cert.pem");
    strcpy(pIBRand->szAuthSSLCertType     , "PEM");
    strcpy(pIBRand->szAuthSSLKeyFile      , "/etc/ssl/private/client_key.pem");
    pIBRand->authRetryDelay               = 15;

    strcpy(pIBRand->szBaseUrl             , "ironbridgeapi.com/api");
    pIBRand->bytesPerRequest              = 16;
    pIBRand->retrievalRetryDelay          = 3;

    strcpy(pIBRand->szStorageType         , "FILE");
    strcpy(pIBRand->szStorageDataFormat   , "RAW"); // "RAW", "BASE64", "HEX" (todo)
    strcpy(pIBRand->szStorageFilename     , "/var/lib/ibrand/ibrand_data.bin");
    strcpy(pIBRand->szStorageLockfilePath , "/tmp");
    pIBRand->storageHighWaterMark         = 102400; // 1038336; // 1MB
    pIBRand->storageLowWaterMark          = 10240; // 102400; // 100KB
    pIBRand->idleDelay                    = 10;

    pIBRand->useSecureRng                 = true;
    pIBRand->clientSetupOOBFilename       = "";
    pIBRand->ourKemSecretKeyFilename      = "";
    pIBRand->theirSigningPublicKeyFilename= "";

    pIBRand->ourKemSecretKey.pData        = NULL;
    pIBRand->ourKemSecretKey.cbData       = 0;
    pIBRand->theirSigningPublicKey.pData  = NULL;
    pIBRand->theirSigningPublicKey.cbData = 0;

    //pIBRand->fVerbose                     = 0x03;
    SET_BIT(pIBRand->fVerbose, DBGBIT_STATUS );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CONFIG );
    SET_BIT(pIBRand->fVerbose, DBGBIT_AUTH   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_DATA   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CURL   );

    rc = validateSettings(pIBRand);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }
    return 0;
}
#elif (USE_CONFIG==CONFIG_SIMPLE)
static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    int rc;
    if (!pIBRand)
    {
        return 2300;
    }

    //////////////////////////////////////
    // Get values from config file
    /////////////////////////////////////
    char *szFilename;
    FILE *hConfigFile;

    rc = my_openSimpleConfigFile(szConfigFilename, &hConfigFile);
    if (rc)
    {
        app_tracef("ERROR: OpenConfigFile error %d", rc);
        return rc;
    }
    app_tracef("INFO: Configuration file (SIMPLE format) [%s]", szConfigFilename);
    if (hConfigFile)
    {
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHTYPE"                     , pIBRand->szAuthType            , sizeof(pIBRand->szAuthType           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHTYPE"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "SIMPLE"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHURL"                      , pIBRand->szAuthUrl             , sizeof(pIBRand->szAuthUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHURL"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "https://ironbridgeapi.com/login"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHUSER"                     , pIBRand->szUsername            , sizeof(pIBRand->szUsername           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHUSER"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Pa55w0rd"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHPSWD"                     , pIBRand->szPassword            , sizeof(pIBRand->szPassword           ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHPSWD"                     , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "Username"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHSSLCERTFILE"              , pIBRand->szAuthSSLCertFile     , sizeof(pIBRand->szAuthSSLCertFile    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHSSLCERTFILE"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/etc/ssl/certs/client_cert.pem"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHSSLCERTTYPE"              , pIBRand->szAuthSSLCertType     , sizeof(pIBRand->szAuthSSLCertType    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHSSLCERTTYPE"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "PEM"
        rc = my_readSimpleConfigFileStr (hConfigFile, "AUTHSSLKEYFILE"               , pIBRand->szAuthSSLKeyFile      , sizeof(pIBRand->szAuthSSLKeyFile     ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHSSLKEYFILE"               , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/etc/ssl/private/client_key.pem"
        rc = my_readSimpleConfigFileInt (hConfigFile, "AUTHRETRYDELAY"               , &pIBRand->authRetryDelay                                                ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "AUTHRETRYDELAY"               , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "BASEURL"                      , pIBRand->szBaseUrl             , sizeof(pIBRand->szBaseUrl            ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BASEURL"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "ironbridgeapi.com/api" or "192.168.9.128:6502/v1/ironbridge/api"
        rc = my_readSimpleConfigFileInt (hConfigFile, "BYTESPERREQUEST"              , &pIBRand->bytesPerRequest                                               ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "BYTESPERREQUEST"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 16;
        rc = my_readSimpleConfigFileInt (hConfigFile, "RETRIEVALRETRYDELAY"          , &pIBRand->retrievalRetryDelay                                           ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "RETRIEVALRETRYDELAY"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGETYPE"                  , pIBRand->szStorageType         , sizeof(pIBRand->szStorageType        ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGETYPE"                  , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. FILE, MEMORY, MYSQL etc
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEDATAFORMAT"            , pIBRand->szStorageDataFormat   , sizeof(pIBRand->szStorageDataFormat  ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEDATAFORMAT"            , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. RAW, BASE64, HEX
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGEFILENAME"              , pIBRand->szStorageFilename     , sizeof(pIBRand->szStorageFilename    ) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEFILENAME"              , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/var/lib/ibrand/ibrand_data.bin"
        rc = my_readSimpleConfigFileStr (hConfigFile, "STORAGELOCKFILEPATH"          , pIBRand->szStorageLockfilePath , sizeof(pIBRand->szStorageLockfilePath) ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOCKFILEPATH"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. "/tmp"
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGEHIGHWATERMARK"         , &pIBRand->storageHighWaterMark                                          ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGEHIGHWATERMARK"         , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 1038336 (1MB)
        rc = my_readSimpleConfigFileLong(hConfigFile, "STORAGELOWWATERMARK"          , &pIBRand->storageLowWaterMark                                           ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "STORAGELOWWATERMARK"          , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 102400 (100KB)
        rc = my_readSimpleConfigFileInt (hConfigFile, "IDLEDELAY"                    , &pIBRand->idleDelay                                                     ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "IDLEDELAY"                    , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 15 or 30
        rc = my_readSimpleConfigFileByte(hConfigFile, "VERBOSE"                      , &pIBRand->fVerbose                                                      ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "VERBOSE"                      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        rc = my_readSimpleConfigFileByte(hConfigFile, "USESECURERNG"                 , &pIBRand->useSecureRng                                                  ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "USESECURERNG"                 , rc); my_closeSimpleConfigFile(hConfigFile); return rc; } // e.g. 3
        rc = my_readSimpleConfigFileStr (hConfigFile, "CLIENTSETUPOOBFILENAME"       , pIBRand->clientSetupOOBFilename                                         ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "CLIENTSETUPOOBFILENAME"       , rc); my_closeSimpleConfigFile(hConfigFile); return rc; }
        rc = my_readSimpleConfigFileStr (hConfigFile, "OURKEMSECRETKEYFILENAME"      , pIBRand->ourKemSecretKeyFilename                                        ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "OURKEMSECRETKEYFILENAME"      , rc); my_closeSimpleConfigFile(hConfigFile); return rc; }
        rc = my_readSimpleConfigFileStr (hConfigFile, "THEIRSIGNINGPUBLICKEYFILENAME", pIBRand->theirSigningPublicKeyFilename                                  ); if (rc) { app_tracef("ERROR: Failed to read config item \"%s\" rc=%d", "THEIRSIGNINGPUBLICKEYFILENAME", rc); my_closeSimpleConfigFile(hConfigFile); return rc; }

        my_closeSimpleConfigFile(hConfigFile);
    }

    rc = validateSettings(pIBRand);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }
    return 0;
}
#elif (USE_CONFIG==CONFIG_JSON)
////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_INSTANCEDATA *pIBRand)
{
    JSONObject *json2 = NULL;
    const int localConfigTracing = false;

    json2 = my_parseJSON(szJsonConfig);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse JSON string\n");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localConfigTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s\r\n", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");



        if (strcmp(json2->pairs[ii].key,"AuthSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"AUTHTYPE")==0)
                    {
                        my_strlcpy(pIBRand->szAuthType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHURL")==0)
                    {
                        my_strlcpy(pIBRand->szAuthUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHUSER")==0)
                    {
                        my_strlcpy(pIBRand->szUsername, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szUsername));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHPSWD")==0)
                    {
                        my_strlcpy(pIBRand->szPassword, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szPassword));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLCERTFILE")==0)
                    {
                        my_strlcpy(pIBRand->szAuthSSLCertFile, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthSSLCertFile));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLCERTTYPE")==0)
                    {
                        my_strlcpy(pIBRand->szAuthSSLCertType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthSSLCertType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHSSLKEYFILE" )==0)
                    {
                        my_strlcpy(pIBRand->szAuthSSLKeyFile , childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szAuthSSLKeyFile ));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"AUTHRETRYDELAY")==0)
                    {
                        pIBRand->authRetryDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"SecuritySettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"USESECURERNG")==0)
                    {
                        pIBRand->useSecureRng = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"CLIENTSETUPOOBFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->clientSetupOOBFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->clientSetupOOBFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"OURKEMSECRETKEYFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->ourKemSecretKeyFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->ourKemSecretKeyFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"THEIRSIGNINGPUBLICKEYFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->theirSigningPublicKeyFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->theirSigningPublicKeyFilename));
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"CommsSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"BASEURL")==0)
                    {
                        my_strlcpy(pIBRand->szBaseUrl, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szBaseUrl));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"BYTESPERREQUEST")==0)
                    {
                        pIBRand->bytesPerRequest = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"RETRIEVALRETRYDELAY")==0)
                    {
                        pIBRand->retrievalRetryDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"StorageSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"STORAGETYPE")==0)
                    {
                        my_strlcpy(pIBRand->szStorageType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEDATAFORMAT")==0)
                    {
                        my_strlcpy(pIBRand->szStorageDataFormat, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageDataFormat));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->szStorageFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOCKFILEPATH")==0)
                    {
                        my_strlcpy(pIBRand->szStorageLockfilePath, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageLockfilePath));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEHIGHWATERMARK")==0)
                    {
                        pIBRand->storageHighWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOWWATERMARK")==0)
                    {
                        pIBRand->storageLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"IDLEDELAY")==0)
                    {
                        pIBRand->idleDelay = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"GeneralSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"LOGGING_VERBOSITY")==0)
                    {
                        pIBRand->fVerbose = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}

static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    char *szJsonConfig;
    int rc;

    rc = my_readEntireConfigFileIntoMemory(szConfigFilename, &szJsonConfig);
    if (rc)
    {
        app_tracef("ERROR: Error %d reading JSON config from file: %s", rc, szConfigFilename);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    app_tracef("INFO: Configuration file (JSON format) [%s] (%u bytes)", szConfigFilename, strlen(szJsonConfig));

    rc = __ParseJsonConfig(szJsonConfig, pIBRand);
    if (!rc)
    {
        app_tracef("ERROR: Error %d parsing JSON config\n", rc);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    if (szJsonConfig) free(szJsonConfig);

    rc = validateSettings(pIBRand);
    if (rc != 0)
    {
        app_tracef("ERROR: One or more settings are invalid");
        return rc;
    }

    rc = ReadContentsOfFile(pIBRand->ourKemSecretKeyFilename, &pIBRand->ourKemSecretKey, CRYPTO_SECRETKEYBYTES);
    if (rc != 0)
    {
        // Import secret key from clientsetup OOB file
        rc = ImportKemSecretKeyFromClientSetupOOBFile(pIBRand);
        if (rc != 0)
        {
            app_tracef("ERROR: Failed to import KEM secret key from OOB file");
            return rc;
        }

        // Import successful - try original read again
        rc = ReadContentsOfFile(pIBRand->ourKemSecretKeyFilename, &pIBRand->ourKemSecretKey, CRYPTO_SECRETKEYBYTES);
        if (rc != 0)
        {
            app_tracef("ERROR: Failed to read imported KEM secret key from file");
            return rc;
        }
    }

    rc = ReadContentsOfFile(pIBRand->theirSigningPublicKeyFilename, &pIBRand->theirSigningPublicKey, CRYPTO_PUBLICKEYBYTES);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to read their public key from file");
        return rc;
    }

    return 0;
}
#endif // USE_CONFIG

bool ishexchar(unsigned char ch)
{
    if (ch >= '0' && ch <= '9')
        return true;
    if (ch >= 'A' && ch <= 'F')
        return true;
    if (ch >= 'a' && ch <= 'f')
        return true;
    return false;
}

bool ishexstring(const tLSTRING *pHexData)
{
    size_t numberOfHexChars = pHexData->cbData;

    if (numberOfHexChars%2 != 0)
    {
        return false;
    }

    for (size_t ii = 0; ii < numberOfHexChars; ii++)
    {
        if (!ishexchar(pHexData->pData[ii]))
            return false;
    }
    return true;
}

bool decodeHexLString(const tLSTRING *pHexData, tLSTRING *pBinaryData)
{
    char *pSrc;
    char *pDest;
    unsigned char val;
    size_t numberOfHexChars = pHexData->cbData;

    if (!ishexstring(pHexData))
        return false;

    pSrc = pHexData->pData;
    pBinaryData->pData = malloc(numberOfHexChars/2);
    if (!pBinaryData->pData)
    {
        return false;
    }
    pBinaryData->cbData = numberOfHexChars/2;

    pDest = pBinaryData->pData;
    for (size_t ii = 0; ii < numberOfHexChars/2; ii++)
    {
        val = 0x55; // Vaguely recognisable uninitialised value
        sscanf(pSrc, "%2hhx", &val);
        pSrc += 2;
        *pDest = val;
        pDest++;
    }

    return true;
}

static int ImportKemSecretKeyFromClientSetupOOBFile(tIB_INSTANCEDATA *pIBRand)
{
    tLSTRING jsonData;
    int rc;

    rc = ReadContentsOfFile(pIBRand->clientSetupOOBFilename, &jsonData, NO_EXPECTATION_OF_FILESIZE );
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to import KEM secret key from OOB file");
        return rc;
    }
    // We need a zstring for the json parser
    char *szJsonString = malloc(jsonData.cbData+1);
    if (!szJsonString)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for szJsonString", jsonData.cbData+1);
        return 2083;
    }
    memset(szJsonString, 0, jsonData.cbData+1);
    my_strlcpy(szJsonString, jsonData.pData, jsonData.cbData);

    // And release the memory malloc'd by ReadContentsOfFile, since it is no longer needed
    free(jsonData.pData);
    jsonData.pData = NULL;
    jsonData.cbData = 0;

    // TODO: Parse OOB File, resulting in a KEM private Key
    // For example...
    // {
    //   "requiredSegments": "1",
    //   "segmentNumber": "1",
    //   "hexData": "8C1E585A46523F75CBDA6A033BE8B3DB9DE6CE7BB25880B65E58C7B9FFCF55B86BD65C4887F9CA522E4BA17FB46188395B9EC1090FB84C6A5CC94A29FAE2B67A579DAAE17FE99E51CDFA6A8192C7FC1A09D43CE5E1B5226A895BCE1AFB80F1EDF8CE7DD28CE2AF94E6B4616599112F27888DAF10479423010D78616AF58EB088EC527B2580C89AFDBE54CADC2AE054D91766D7A9B3140D6051913EEA2D01F79FEB4E1FD2F929F56EC2D12B6F0DDCFD32CD153A9101B355D33BC1AEF473C4073AD13F3891B51B56F8C482747F28B9361683FE93F66162CA027C3DA5692D06C8526C7D5BF6AE08FCE91489A6F59F49DF23E0F5FD26A12D1AC4285DD6DB07A9EDE842A133F4AB4B13C3C254E0DBA50F10347410CE5CB4E369E288AD472C32617A80AC689604E92B49CF245B31951ACC9CD53E10663EE48EBC16BB38A2A4FB7D50DB92DFC5BECFEDCC7B0E25A0F1B83E682634B908AE2AEEFFD89567064CD3861213281C870BF55E82C09ABC18DFC8C98A5D34C10DE8BBCABE04E063C4B0E0C4BB8159EC8D409BE60431DC2A937071C78DE63069B01AD63BEE66CBEEFBD0385E19F9F63C20D2650473F0ACA28CA373CEF5234CB0F68262F2A4574F70DF2C0BE6028574D2D07C30759762B5C970055D872E1E50F252B7D3E6DFF0CB0FC9B7E2D35359AA1D9DBEF22F0F6D127D385C70460C2F59D48647945C3771C47A58D725B03F9B2C24B26E40657A9D90FDCDC40FBB535D0D02F2DCA8FE3A53B30F3B35FA737DA492DAD8B0EDA042E6A5D5F6F13B5902E55BF3938A693AEA3CEC4CBCD5E927BA1D3F7E51252F27B05BF8D8F5FB0A8D2598ACD438A9B05772925C75DF1AD2B7B70C810D1A2CC393DBCC832DACB6FC8D0104F98AD3B5737BF1FC9F42689F12A1166C7E1C495A3091C623FC4222267514D0E6B1E51110516D0FE98FFBD64B41093BA591D4FD74AE3CBF8E14CCFC92A69930BBD4BD5687358B527FD60F95B7B5F0C33533CA8043CCA5CAEF56D3D7AE8CEB8465FDD4C039265A0E337F447ADFD12092F268867EC2192CE97953449701F5EDEC446ED7CF5725123C4A9952C5A3C1DE3FCED4BDED9CAC4CA48E3489952AB1451823E477565CAC52985189F681779489D9668AC804E06AD05CE9FE16411DE9AEAA5D177CEA2D71AFDB340EF9BB4D23B1112BF0597D262A092EBCA9AED15C60382D98CEEF36826507488B893A5F8E81C35D90AEA7620DA490A01671EDD6A1907B376E70E5285C114AF53A001C070A534CFF9F91ECB986505A35957A7E7D26D6BB793934CABFA0774BB469FD07F912C9DF1F509CEE02EA9065DC321B79D90B28F351ED91FD5BEB39E765F971062FB125DD81B0DFB617E447E32AE4208F8DF93B2516C02A944A4A80374F325EB276846252A683FEA6F92CFD3C165A291F45814A24E7075899D0C1F19C5E195464ADD0B4750AA0D8D07A45FDA15D46E4E0F07279C9934922DE9E9925CA2746FD1D5E01944C0DD729E54088C06D41FC440EDB9FF13C34EC02E36DE3434B9CBBE0CDE93F054AA5F82FD3AC39A4BE3477B66EAE69418CC3EE3ED408191B890D31478D7F5E830861CCA1B55B060251CC99B7D673A78E794A2A05C32C4BE11CED2199784CB4421E40E697FCECB53335AD04F37D4E3F3ED7049EFA0516F2E2C73214E36A39E136F65CDC56A86E7C9A46CAE6C181D823F5D5598B133D21F30365C4D674D3313F46AB1B9647C51A13C887807CC1F38FF10EFCC8EA1053DF92BAB2BD05F14A41707C9F5AE9E80266DEE2483208A7A5F76954DE113A4F4E95080B299AADA320410BC9E907BACC47ED01E0FBD6351952C5AEA5525296ADF26B2476BC91828B06246AEFEAD6D5F762DC6A52BF918DCBA85E7AB7EEFE69E27519C9894215734CBC9E4EFA1A7D525E3739EA41421C2B06718FAC608CE57C7FB1B95FA64BB810A7A6C9DDB288918931B404D31FF576ABF99D57532EE902639132275BD01968ED0E359F5D171A56655D59D23AEAA44CEABDE4FD0E96C290FCD5F5FD3277AAD5FB5FF5AFDDDA6D0EE90005A1A669D2BD1390A77D5ABE29DC4814F669504C8A086517518CA3910D37219C96E0CE41FBFE6C52099677C68747290E4C0DBECC162A940305F2BD77B2DADC9CDBEEFE645928F8C393F8B045D94692406865CB4A98DD04D1056D05978A60156C8C33D6D1EDB008B31A941BCA6804184D4774AEE0B562B48473407D325A55784AFC7D8810DAD22AE3456DA1AA1659FFDE9DA7CBBC2ED28F5B3D2F7A9584AABC1D401280B9490FFC59458449618EC321DA37A0ABEA249B16B9BAAEFCFB991CEBD8DB4ED1B008327F6CD70BC7ABBDC1C26B0C671B5558869B287AAE49B604B67F762238EEA65FAC629BE61D71F67D60916F4B8764AF35A5B8FBE7CBC68E56E724910AACD63FD2353ED743F44AD96ECBD90532AE8D87C963BF5B96B1F9ADD412F9788BAA003A2E0584C218546D07026EB831B64D05AF14C65FC17FD0B300859C6CEC9366D3DA03860513A2F431F36CAF49BC1BEDCE2E12DC9D720FE83356430084C10CEDFC150F1B4A16BE2E41F16136638F63EA629527BEEB4541705FC275C9BEA274537D83B6217D955F1DD7B8782D9AD1EE8544F4F56778F707CAD954A182DB7C5A73D99D88A3F106BD2C404982B851118B53000A96A859AE00E26A19D2462DDBD634F6CFE521A5575DC90727E0E7D9F0AA0294F2644FCF3A77898E164B2435F232EF26C3F1994801CD5B1C5E48DD019DC9A79A74D99228D80C77E8BE81D218CAEDFEE1172BA4B8D4E1FE5241397BC7C4B1BC561B849E8A24A0EE44CBBBB25BB3424DE943FB6EAD81B8DFF3A0A4CDD257360ADE22BCD7642D15D704A8049B31D7ACA32D2C407ED69FBA02826344394AC49B51B92BDFABCBE76622E5F796E5B87E07FF8A231586F15A7AA546F16B7671B8F010FEB84012DC48E20848AB4A31A63462F5C4D2D2406547950A9D7EE93FB9692388B4BC54D6C439271298003A11EFD023147F07CE2F6072C63547A7D957E94491E3F201850D2DFC058F29E3151AFEF8C2867733A97CF00BE958154E2F5D7F5EDC31C3FD04B029A038240BC6A4C03D85F5985CDE0351C05AB3C6246A218BA70B3E0A189C985B810B3A6A4502C9AC197584B4FB73516492AD6DCB9471E7E3D46FFE26E3807290F00D9286443A6C9F2515317D3E608DE359A6484A32E2F14FE3224A0FEF23B3BF28D55E3C7FAAEB1C62095E7F019BE870079ABB81C830E9FD42A0963CF13C91D020A60B2DAF3A0455E81DAED8F37301B7F9D5086430DB74DC53B9E23EC5676D44E2E789D36D3B8F2B0A2EBE62CDEBA5AB516DE997F243CC36B44664A9C83867CE0E1EBA559B76DE25CCA2C5887770B6B37EE2B0D622F4A1C76406AC0496EEEEEF747111E4DBD2D4179B4988D66D2CB4222BBDB986E066E20528B19E1414E3390C8ED3922D149CA9767F7393DC46D1A0DA22CD3D549AF450162825D7CA063906CD9BC7A6AA4CC54F20A000C83DBBF6199AD3F9CC6BFDF9CC20DFD4F34D8B5A2FD80232E81DB9FA91D2C15B0EB0FD1B8825A91A204E89FEABC343CC105A8D0CC02BEB739891ACAD38CAA7C8907FB651A655BBA19C9C7D38BC72099EE331EB56F47067B362C9CC6C10A3460094E272D82D1C5630F79C670E8A8DC316E2F6425B5377CD73E08E9076D8C7C7DD0BEDE424243DD346938F6BE03BD48313D2866F712A5CBE47218EA83D83E29D3FD7FC1C16C50B185C6577ACBDF6A7E847BAC1C63AEA1D698D3C41DC4151F0B858A55907801E78A2B52CF7E1033A50F9E256F9638C7EE96AEFD70EF3B79C14171AD25EBC73382BCF46F7DC53D9CD5471EA142C77906C2110E09791A1B624168DCE66B621436BDEA68ED576A563A9FD4EBDC33881C2797217D9DBDC2930CAA5D7348551A64A0B87775405C6F2A1A6D2FD054EB0FB413EF041CFA38865C38E9F9BA4AECFFB2829D4A509A862695D89A3BCEE7949F2C30F08870905198B7345860301B813FF9B9BA2986706548E79C871786AD5F7D91D1437AB3E24105F84B9D82AB7B0B5065519F2AA9A766EB6BDA8174DAFD144653B231F59ABCF2156D3350F50DE2500F35E29C244F495F3A95262AB665FCF5205FD12B8E8F396E1E7E0E792313D7F7603465CC7010F710F631F90B47246A9CCC98F144B9C19A84AE9C035997D0EB46FC692DC9F4EF65E73277FD19CDC73537548B2A12F297532F733BB630ED2ED2BD5B531190BD633661334A2F6042FC557420FD5A8994C184E0526F78C781775310FBF72EB88FF5974BB25B2667F3633ADE3831326E8647AE11B22E0E5C2C2B63488E81C2FB096BD472DCA77155CA6ED65FDAA6AB62EF8ED258C1A49AF3677CE665C814F473A7FB5421DFB62B2F654DB89F841E72B22435E0168AE2BD5850A880C0A15CDC64523B75BF943F8D80678A87A28D8F3A628E708465B20F3F3DCA73BF76E2D9BB9A456DD6AA2D8B97CEA1A43AEBC8159FF6C76D45E4800194B4126888DFFAE8078EFA71C2B6C809E27ADE5B00CB1F3BFBA6D576E370DD8F2D4C8707E5D0EE5564FB0FAC653EB8EFA675FDE25389906286561CAB7041A37CC1B3DA085F508569F8B2336EF36E9F9473FEEE87A65613D3CDA47D3392416A4308678B89326DFA708AC36F2BD344E21430F69318A0ACDB590A8EEFCB44410CC1B5EFC6A82FC5E596F4D3F9E8F42F8D2C1B66302F34F6580019D131B8CE0CDB088E378BFC339A61AE804F982EB2835E70A9E7BEEED6F790099FAAD35D3BE62A2A37A008057A482C0090A90617374E81B23C6E90F1BE3B588946EF2D77F13C0AF8C6C2377CBF3B32519C03571350755A401DA1D89B342CE19F9F7D4D507AC26D53FF7E3A2FC803FEA944A895E3D83AB1D2EA81CB7F2278D6BD8135767461BBD78AAABC46CB8E2665A609D0BB977133DF718A3FADB60F391D70D574660CE900D6F057AD437F654D5D1ECACCF268CC50A37710C227F348B5407BA64387410C60C26C4C1998CEB605D5D6E48EBB9BAA3A9CC4861FBB9F37947DD21629D61F86C59CA7793A64BFB51EDEAF8E4265F315EFA41C60D5E08562C908C95ED48A0107DD2FA6C9D62BB33DD3BBC733BA86E83F0B52BFEE563E47B1278C7843E2654F2363EBAE737DD5742893DE0E221D55D2408A1B8B85ED52A5D06762577D2D888137EA2DD6B02863918C6DD69E3C0A444800752F1FF6A9A9DCE6FA6E8C006150396B83073E4AB4BDDBBCCD97C465D978411411D1E6EAEFF91022AAA7D029D183F62F0D455D1E7E3692FEDCE3D87E3058C41F878C1DBED7AE8422B51A21586633A8B36973CFBCED410F48B5D3FE12AC73EC4EE2BF1F4B66FEED3C546C6D482898F2AF1D3B8AF75A4B2BD988AE395B52012752CF5864932B79EC9E51C493E74DF4B7F718FF21CE82A96C3B20D5001A190EB8533DC22FEB7F41DFA49B5A5B6EEADDBD5CDCB737AF2F99DA42B2F26AFB4108799D2F2054061F0600CC79B8AB0D0B06ACBEC71564BCED050C87120FBA56D0CED631ED2DBAA6B8A65152E7F59694254294B4DA340F2F09987798B49150C4215EC9690B4B3CC80235A818DC2489F23F538655E8D02B5C159040A6FAEC0EFF03AB50F68F26909E81E034D31DABB8B5CB2B6B891E320329D09F5BFC5B10EFDA7756E2BD6E9F5025C77F4A16ED3E70074EDEFB0591BC5477B84C8192B476E70FAFF4964188F4497EDE8C27D301CDC6F54FEDF24164E23011AA690B9E129EE74B4B5B3B999DE2934E49D3416CCECC5327D92A02057F35EE6F270416109B930404FB4A87312709D73876F347CB1C0F9D93435E6CB1602CA9CD0477202E0A8923A7A35228EC211D77626ADE1E3C76A6F220E916515885138314C6A19460FA11490635C33F747C6ED678508D14758C2198A0F73A835E5363A61886533D6D0D65B8EE79F3CFB0C8C560DD49BC3AAEC0C485B8EC39046BAA7BAADCC82ED32A0F86A1C929EE97757562E0EB4299AC01877093E9F94941695521851A5007E8449DAFF7E10CB42F2FB3C4535969A848443F550386D3F8821C8FC5185C5989DDF07A8030A1018280B9D79D2FE52995EF3CA572C6522B9F9864F6CB4CE4E8683D51B2CF3041A7724BDCB617E322BA23C1176DFCAEE474195642F73C507A12CA6BBA3F9CEF7F78E468C695D011910EEE7F5079ED8A8EBA538B6CEA7D2A4713C07045599CD20BB4028F76E6B699766983EEC2860C364EE365549B714872418A3A4265E4A58E6B3EEB5896C28F63EF34A80186A7F5BAA0BEA3D31EAB099E54D3482D19CF42D140287B7F933041330D02735E37EF99EAC2E2F295D575BF68918A5F8F28A758990DC95343BC0EC98BE561CC0B672C3B0AD0D128ACBFF339467AECC781D4661FD12B176F5A789D39365630523A5350A7867DC4C144CCB209599AD1C0F635870AA88A5B4070E3081A3E0E36B8B1EC922CA464765E20BC21733DD222B1506939B03921DAC6A98081EDAD81134D740C06BAF6C40C16FE5BCCBCFB635B85B2D74B14CBF515278C4410A3ABEE29DC7B83770287C95D3D5AED2A77F1B1EC471ACE677BFE7162C2B92245CC62065ADDE29973ECAC986EEA391699D6F76EFC78EC49AB5B6C5A7A834C386D679533B389EDFBECC5C41EDDFBA485D32B92FE623D58D3C4F47DEBA9DD152097038B170260D94394628B3EF47FD2F89ACE90AD77349C8A9F200BC983743B375C72896178AD08D76D0997F335119CFB43D9D8A6F7E5AC822993F2F2CC0DCD8A4394955E9CE19F7E1F8E08045413F28E20517E87C5A3C70687EFAACAF6B34F39A17345B3625A4E57F97EA041E261A6F5135DA69E07CBAFFF2ADB12B8653E7E427A2E982C1C6DBDBDA7DEF3940838304AF438952F463EA53B31345D94E514433341581E325DC3DFCA1E8A11A3497161BE8CE449296CA20C58EA9A26778E33D76F961B1703BCC75832643FE43F479F4B7CDAD47C080CD342CA09BD9001539EE8474ECA2F8C6416B65B80122654FCB90467D428BCE6BE5A55BEB669CAA7EB792775ED908335AB083153B5C2003AC7DEC787EBBC326327BEE18A582FB16C662482B320D85730FA1FFE5B018D7EB17F0B45B873F2E5E9E311D29A03F6BEB39B903716109A5F0AEA3B9E3F98C6D58FFA7225585FCBD0D144A86142A54E38648D2B23245C57A922244AFD6A9A99706DD16933236D1BC8A091A47B3A5626E55AEC797C9721758134D9A7EC6EE3CBF124C8EFADD2C7621AB881262DB7682A98E6515EA59B573088FFE9B6BDBBB04FF46548596E259EA62154973676A265304A5FE4C339BD544C5902F2FEBF4D827852717B3CA5C39088A527AEB0584B39E9761826AD150BF61AD127D22299C9B941A5DA6B851BF00CBA38A7648A879736925E187365587B005538C92BD6F0FEA5035F949C4F9AB6B7938517D9E758BDB185FA0BDB725C2C658E7391258F0F5A28D001017C081222DB16E42CBA62526EDF9CD2030AA06A7C72E8FB2EA715679508736A9C9DF01019F748CC5ACD3D21160BFE485F1993EBB46345E0886C141E9A09EA0F6DC6092BD5D2EE16300CB1037F324AEF9B59B5152D88026604870E5A1871C7FC7D78137288C9157E49F62A353BF87E0F33A93BF2822A6D638066398C3007ABE3429D327867ADBF0CD982853FAAC223B975D459E684DEF3CD90F57D9F24E276EFC62EF7327C050F3892BDCB75FA36BB8F84F9FBD9068C321AB8D9EB3C95AE28CCC0211EDE34CC8DA41F2ACFCB94F4954F51066EDB33F3A4BCBA91CFD4E50A93D809212FBB14D6E4B29BC613B4523FAA12A4C6A035C6DB708A1191D23E5245F1466C62985683BB7B2E8DE5933268388F50C7CF1958D2AC88A6CA047E2126A0864F1531BC5D66DCCBA92EF6FE608B1DD60F2E15486B03523836FC2C2C3395BF054C3B4E50A0679E202A926728F8FE90AFD1C9EFB7CB8BA50D7BBE556BED10B868EBE053D07175A69AD840956CE53DCD68659A5BDB4E9BD745195A2585AE3A95EA6E76D4F9E0EA7B9C7ED8D53DDE62EE31072EC2ED15B4B125AEBF18D8BE6066AC0299B816A88CF7733C2FABED5FB7671F483A2945CCBCA9273D7CFC4B9D7BF1AC8C4A22708FF7BC0FFD079D1E064A9636F9FF20604AB10ABF420F4F4247F3C892693F074259A3F0BA483E9BC564932047FDC43D170743DB5641F761984FB47E2014C29B3B38FAE7E601DBDA98E3CA75C2F8136E5A945500359565F19412DE8C06594FEB193D124BF85B1419D66D58275EA67B5A9C8E8CE9F89C7C5817AA6F6795CF478BEF0A252E5929A797C1F56976E3EC2681EC632DEA9D5B3366668FFD4856A5A478136ED3E06575CC98DBE7B976D8EE240B36CCB25512FF9C33139AFE2210802352E728C00E433728E8CCC59515F4F51277FF03EB925FFC32CB95E99F7AEAA8F24C35D1D3E7C86C617430488C6FA546F847CC5D296A37A7E3F3A0C8E4DFB22B944501E814C28E89109DA478C2E43D66B996359973236BC1823AE5A4F2073AD8D16EF96928DDB662B22B8CF1FB418E848A34011D10F10A9D7685CE9989B44BAE8218109A7AABE235D922A1BDB951594996FEE736DB5EDA2217861DE7D833E925032EC0C3B0A0EE7108E8CC0D006162142B92F0531F4467CA7EFAC108EE45CAD5FEEFA5B007D7902D261AB76B945E8CEA8185EB0B89D6E8CD2E3DE278F392326ABC69D5A809CDBCF21CCB87819C1C1085D26DC1D14B43AB3C41AC37DDF5546A1EF502953ADD86E636E5BB4499B530C8E48FC90F2BBFC790D907B8138E643F458E76F56B515110F5136ED755C5E695ACA8A337FFE4AD3AA67AA5B634BEA2F6AB4BE15DACFF4605F9AC3C6DCA522D484EF92F7487F3B5D7CF5BFBBAE220B3430C29337215D4D396450FAD3A9B9E8A4FF8725B4F9A8DA03CEF3B59DB5DB19855A3EE67F1D22CB235940FA785D1C14B6222CCAF02679C34366AD477F9368DB5961764DFC59915674DEBA209B016C9F9FEC3D6CA409D2AEDABFC5C72CA1547F48BE8FA7ABBD523BA33CAE0783B6C8B90D34C66969B9D232BEC0F01F0895795695A572C11CBD4654A4F1AF93E1A2B3D56A56251CCC87E3F8D7E4BB6D6F35D55D2ED0FE62CB336CFBD2EE11C4D24020302B6708213482FEB838D996AF5D6FC7CD5E5703D3B185482F23E82F56663C390D4935A82DB0552243CB503AE832E6EDA60572CF152F42CDC9E4D16EA11FA99E5877C67494A592826ECB8A694E15131818077629510F047D0BED594CDA7E2250A7FD4D850D839241643E7A93C70104E14EBF2C889B276E55E32BA88B702097C9111D5D7E76A309D9B1ADDA8DDE5159FC6585E913F4DDD9E7F9E0375C21A27732F6F822EBA752F6A76BCD236EC551B0AFCFFAAB5CF38DEC69D54254D6DAB3F7A14317CDD4DDAF537A3AE32871D4509785F6B8A602A5633D398B7B03D1ECA3FF147FF19A2982CE3676B1BB44242150932A433A6F48010A34980DC5B8F3C0CEA8A76CE9AA08EEADB766F994148634771B4E499438F0999FBCD421CD66DCA8221ABAE0C7A7EEE19A14F6F745A0FEAF0FF2CF4098608601A88DF39EF8AEA77A8E993D1A086CCD9C9675371406C349BC8ECF3607BF29CC0236518A3D98C66CBDE36A1D3842CC03FBB302E5E6E66BD4AE9C2223F81C4B76B3FC2F9FA80326D44DC75C1769A45EDBE1DBA4DEE1F6D9A3331C8DF125ACB52F1615782AF26D6951830833983D287BAD5440111267684E6A99A41A540EC9A7FD77ED244A7EED7865214CD0CD25D66D363AB8944B20FA6F6D4C7B9684F7A5DF85CE9D91445EE019E3669C2CA9E0E35ACDEAE9F470B6CDBAE95967BBEC77D72F9552B4F2E53BB97C1148D5D8CBF77D49C63FCBC9029C1480E4C3FF130CCB624B7D2E447004A66AE78B99E070C2BFEDF49E0E1B3F4421F78707C5445224F18E43E92997328F477C2C62DB2AFA172F6E39F0F015790C80FC51466D62089536504B0EA2FE3646E851BA6A21D79FF3C785269FC26EA42A2F57734526556E7A58DBD89B40D447A4E09260F7792D5FCA7D345FD74E30271F81F8C91A9D17C896744F321E97F60B76C102D0F6308E70A8E5A5F755558782D69BA68A93DE3E08C4D20FDA0874E0A096707DF08168C01BBCEF58EDFFE8C78DCC6D6FDF4D523FCCD2BACDBE6B44BB70D52961F17EEF60906BF0463829100EA80109BB6A3ABDE39172F9E78DE0DD7ADB31EC6936D5F179E3968C285C3C08A29DFD1997DDADF9A2C22B7FC2C608D85C5565A8DE1D79C053ABFF8134960445BB3E668F12B7703D465194DF946FF8E15B4D6CD1E0AA1D843FE7F24CC552EF05E332C0E2ED2D6FBB199151370C4334D012EA0FACFDBB59AE17B4E29AE90321AB16EE63231BC51149B31F79B20DE82E2EBD671BAFC6D342829CCA01FC54A323DC1817B8CDB068798200D785319946ADF71442EECB106D395F6404F90120021CDD1DD7DAC3D5B90184F7AC4BB4977C691DD0F03A1C3BC8C5F6549B88FA07FE0BFB66A7A148C79FAFC31580CF1644416110A3425911226F4E0889A96A8AD208CC569A9CD0B73F0E597A10118AE105A24325165014E139051BF1BFB67BB6894E55739233F0DB4B9B512E38C2DBF186DE933DC55561179DF6EEBD1E46812737BF3BF4B7E5B15A005F359FA9CD75DB54EDC05275AF0358F996D2656E7D2B7208B08B533A2E373B9BE87020EC4858CA49C80F35B93AA58F7ECC5E6144188B9D32E2CCFBD786FAB1694B47989148A09162D65F23554FB0753197EA45958B1E59FA098D6EDA09A53F0DFECCC550B56B3C698B34364962A78E4431BC1DD44F58CF6EF747146FDE9AE8562C0AC5AE1CD57B357789AE235D7CB5D6D681EE76EADC8A59329EC75D1BB563E5B3EA70521676FF8F01661C3C7BB12AE07AE6E62707607DFC2090AFA39AA073881F389AB082FF209B21569CCA4B6C6E17F68E60E5EB1309B27A5FB66263BE56E45C40CB1D971570FBBEB12D14862E8A9B296BD9025849E48E9C6210BEC94842CA5A9FAB8E44951CD3F3E747365CCFC808B3C82A8652E1BDD52A652399C7CB7835C4A3F409B4757EA9B962269D8583920B5F889259ACFC626261CC6CFCC7B7B6EB8C5D6A0AE8440398B6AD0F90BBA824AE4F37041E5FC74BA20BC5391A0AEAC0762931C6085F94209140A6F57FE217B3E7D43964359F691B2D074E47335D1C941899DA18DF715A8FE49AE459590C65DE4721E3202B37C73B594DDEC243096517B2AB42FD2F430427EED5FE0AFAF06F281920A75C8DCE38BC5FABB3E880B10F53818D52B448EE0FD46516CC7C0A520EBB47545BDAF013758D0BEB3226A3B539E4B6E8F4792C02FF353A0574B2DE8F99A81F88B92A5346E86619660A7738103CA7B9B9110073E1ED215630061F5251A3419A8768A899D3D4AB574F769AE15857E2B73AC0858AF7A52EDCA170C0D77018EB9B1B9C866818C1684571ED0A22F8203798EEF481E6B0B41511048B9BDDC293BF5E9E0CD28A26EDF3B4875EE0D9A2C50822A515D4F329EF2245304BA14CFAC6BB1EE91FA5FD1ED6568BBDB4422EBF356D81A083E49A2AABCDB1280BCF6320323001534C5879FDA3136C0725E569D497807F8CC685F2F8F9E2D72CC2942EC3968E3C7E68EE5D34EC92849134AD0D8C7EB6190B3B47C2B20A52A256001F303FB231584A638BCB062C419AF59BEA7A256D059CFC65DB89F549333B7DD1B5D655C8CB6A3E2CDD944BB23A62E3D783FE75C7FFDEF925CC94303DA757774E07BF46008EB85F02A209289F6B49C1E84AE784706C809818BE51B50C39F5258A6ADA016DB77293D7399B5F720AC153156179259C811BA33E4A67A62CAE5E686068AEFFFDDAECAFBA9EAE0AAB4FD23405D19BA67CBE56497F419ED1BBBB1C84389B669FDBD84C540B05A1E404DC1DC7BA80B20C1F0BE816306DB2FF871F258A499F77E67918A49707770319A775E5D4B4CECF8D7BFF6F14226AFA06618C200580E7777209E3A90697833BB641EEE3F8AC2FDD099D1DEB6D629E5515A7BFD1A415229D06E8F90E8B08E901F71697CC9A7529BFCFA6A3DE2F15A20838F64BDD34100F584AEB26BB582D6C2B295F5D52A69ED49EF09769EFDD9825D846A9E45FDD29C8F95FE15EBB439C2D340ABFD995C0CB8EE977783A73A1F254B686501B260F5212463B0639C9E1BE9FD41E3562FA7DC904A0E6E6E90EB50AE3ECA676C827899045476A168FD26FF5747862FE7CFF2F96AFECD360DA12A39D97A735C103ECA419AC08DF1D476957C9763C8FA9B71757371A8334D7ACC9B2192617BCE2E28BAD167B706FBCBBB31802C8A822DB1E34246D86CFD83F321E4A54F0B06034C67AB1132F66B9FB1620597E18B1CB9C54A8D6AA02C71FEB531DD068B4E62C0F1086F830AD8B384B2E8A1F5F8CDDB749D9931592D63165122CE8775023BDF66215AD0E1F00D4E9425D15AC38C6EDDA369AD56F7F565B3CA29C586257091449F4D87EF23AD52253FA8D87A0C2B467BAB56CA725E211DF249B77FB740E34B0C9614CDBA309724A6B6DCCCC578B87274459FAA2F2DF29AF2CA0A1E19329CA40D12671A018671481BB90D03166800BD3C0D24BAE3197C650291C3E0DDE62DB08DADB7A71D87929BEA56A17DA6D645BE43E965B396155F07FB201481019B2097121E7775B71578988064E4AB7D450025A94B790E69CAF594D666646019220F9B72E2136D06A558D7BFE0FE83E495788D73CEE7B5DDD600A1C2D5FF693E2B0ADB426A15C2729554740D75890809D2CAD4647860A6DBCFB64C1DCDEFEBC23E609E059D0DA867CD6E56BE450397DDF1D9734A04EA63606275C97E7A099250AE43164D8AD61C5DF840D49538CFCC28DC4B05E88027F3FD3421E69C352D7B7C287697579C45BC8BC0B21D96C4AD877BCD4C500E36943E1D928658B9E3ED779279428BA2585EC8EACF160EA779C42699629E3838C0887ED76C4AF556013DFF94BF3C8C3317A127DA5AE77218D91A6B5A049E5659367E42371F22FA984C07C6929ED8A2A7F99AB06BBD86323D9449E70A36CA4F3E3312F3DF5D186E4EB4AC795EEDFC56D9E58A7B2C8D1B6A68BC60C690CCE8022AA617506B012C82AA8D45E0C290C494719C523E2BBA539AB28869E0674186F3D0512C90FE9046A0D91F370B8D18C3D59665C3443B94FC79A219B368BCCB7BCFC81C29736A219A7AEE9FE0FD235E6A482049768482B4FBC41B2291B8D0F4E31281513E3303EEF1440934DB7885C2869CBD61773A6BF75DFE144E81E3556253A88CB6314D3C71F1ADC347F7BF1434E49E4CB42395594F638435964254A989C86DF221F06564CCF4248D77D9ABD9D8EFB99D16EA1BCC51A03E6F9FC26FDABFCD1FD2C4EC86D139DE41A71C7E05F1A6C2695D829F2C45F3ADA114312E130DFFE570860B4051F3E682EB14103614A085F3598F1CC4AF3784FF4153F15AE33A483CA3793A6894763E6EC2964EDB3DDC341A3B9D7FF10FE92A674DA6200520D48AC94CA00D496700F28591C1843AF5020491335A141B725E2BDB3613733943F4F47B35B1475D3C8C38F42A04F87999989D0453CD8AF8EC8AC93126744A8DD57B8574758DB55B9DC6B6A777857FDB58708BC82EE1FD2E440EBB9E0787D14E319570BD836688C77911B8E8B6634075F3B109C890B60E44A426DC710B538ED55439722222CBA017BEF2C4A5251C0A94DC817A381951DC46E880A2965D38759E4B730F3BE4B6A5E000001000000FBFF0200FFFFFBFFFFFF0200000000000500FDFFFAFF0000FFFF01000000FEFF0200FEFFFDFF0400000002000100FFFF06000000FEFF0600FDFFFBFFFCFF03000200FFFF0000FCFFFCFFFDFF0300FDFFFEFFFFFF0300010006000300FEFF0400FFFF0100FEFF030001000000FBFF0100FDFF01000200FFFFFDFFFDFFFDFFFFFF0000FFFF0200FFFF0400FCFF000000000100FDFF0200060004000000FDFF02000300FFFF010006000200FEFF0200FBFF010002000600010004000500FDFFFEFF01000000FFFFFCFF02000000FEFF0100FEFF04000000010003000100FFFF0300FEFFFDFF00000100FEFF0000020002000100FFFF020003000200FFFFFFFF020000000100FDFFFEFF0000FFFF0100FFFF0300FDFF0100000004000300FDFF03000200FEFF0100040004000000FCFFFBFF0500030002000100FEFF050002000000FAFF010004000100FEFF0100FFFFFFFFFCFF0300020000000700FDFF0200050000000200FFFFFFFF0100FEFF00000100FEFFFAFF02000000030001000300FEFFFEFFFBFFFEFF00000100FDFFFDFF0100FFFF03000400010002000000FFFFFEFF0300FFFF0400FDFF030000000100FEFFFEFFFDFF02000600FCFF020000000300FCFF0200FDFFFEFFFEFF0300FEFFFDFF030004000000F9FFFEFFFEFF06000400FFFFFEFFFEFFFFFFFFFFFEFF0000FFFF0200FDFFFEFF02000200FDFF03000200FFFF02000100FEFF0000FEFF0200FBFF020004000200030002000400FEFFFBFFFDFF0100FCFF03000000F7FF000000000400FEFFFFFF0100FDFFFEFFFDFFFFFF0100FBFF0200FEFFFDFF01000400FEFFFDFF05000500FEFFFBFF0200FEFF030005000100FFFFFEFFFFFFFEFFFBFF020007000200FEFFFEFF0200FEFFFEFF0000FBFF0400FBFF0100020002000100FEFFFDFFFFFF010002000300050001000500F7FF0600FDFF02000100FFFFFEFFFFFF02000100FCFF02000300010001000200FEFF030004000000FEFF0500FDFF01000300FDFFFEFF04000300FEFFFFFFFEFFFCFF0100FDFF0100FEFF01000200FFFF030004000300FDFF05000400FDFF00000000FDFF0500FEFF0200FCFFFDFF0100010002000200FFFF0200FDFFFFFF0200040000000100FEFFFBFFFEFFFCFFFCFF0300FDFFFFFFFEFF04000400FEFFFFFFFDFF0000020001000000030002000000FEFFFCFF00000100020003000000FEFF00000100FFFF0300040002000200FCFFFEFF0100FEFF02000300FAFFFDFF000003000100FFFFFEFFFDFF0300FFFF00000300010002000300FEFF0200FEFF0000FDFFFCFF040001000400FEFF0000FFFFFAFF0100FBFF0600FFFFFCFFFFFFFEFF0200FDFF010002000300FEFF01000100FFFFFDFF0000FAFFFEFFFFFF010004000100FCFFFEFFFEFF010000000300FEFFFDFF0100FFFFFFFF0200F8FF0600FFFF0100FEFFFDFF0200FFFF010000000100F9FF0300010000000100FAFF0000FEFF010000000100FDFF0200FCFF0100FDFFFEFF03000000FFFF05000400FDFF0200FEFF0000010000000100010005000200FAFF0100FFFFFEFF020001000200FFFF03000500FFFF0000FFFFFFFF050000000600FFFF0500FCFF030000000100FEFFFFFF0100FEFFFFFF0900FFFF02000300FEFFF9FF04000000FFFFFDFF02000100FEFF00000300FCFFFEFF00000300FBFFFFFF020002000000FEFFFEFFFFFF0000030001000700050001000200FEFF0100FFFFFEFFFEFF060000000100FFFF0200FAFFFCFFFFFF0300FBFFFFFFFFFFFEFF01000200FFFF0800FDFF0400FEFF0200FEFF03000000FEFFFFFF0200FDFFFCFFFFFFFBFFFFFFFEFF0100FFFFFBFF03000600010003000500FEFF0000FFFFFCFF0200FFFFFBFFFFFF010001000500FFFFFFFF0200FBFF01000400FEFFFFFF0000FCFFFCFFFBFF03000100FDFF00000500FEFFFEFF000005000100FBFFFEFF0200FCFF0600FFFF0200FBFF0100000000000100FFFFFEFFFEFF0100FFFFFDFFFFFFFDFF0000000000000200FEFF02000200FCFF0000FDFFFEFFFEFFFCFF010001000200FAFF0100FFFFFFFFFFFF01000000040007000100060004000500FBFF030001000100FFFF0100FEFF02000400FFFF0200FDFF0300FDFF0200FFFF0200FFFF0200000002000300FFFF0200F9FF0000FEFFF9FF01000000FEFF0000FCFF0000FCFFFFFF020000000200FBFFFAFF020001000300FFFFFDFFFEFF040002000200FAFF0300FEFFFEFF00000000020000000100FFFF03000300FDFF000003000100030002000000FFFFFEFF0500FEFF01000200030008000200FDFF0000010002000300FBFFFDFF0800FDFFFDFF0000FFFF0100030002000200040005000000FDFFFFFF0200FCFF00000000050000000200FDFF020002000500050004000400FDFF0200000004000000000003000000FBFFFEFF00000500020004000200FCFF0100FCFFFDFFFEFFFDFFFCFFFEFFFCFFFFFF01000400FCFF03000300030005000100FFFF050003000100FCFF0100FFFF02000000FBFFFEFF02000100FCFF010002000000010001000800FFFF010000000000030002000500FEFF0100010001000200F9FF0300FEFFFDFF0500FFFFFCFF010000000000FFFFFCFF0500FEFF030001000300FFFFFFFFFEFF0200FEFF010000000100FFFFFCFF0000000002000500FFFFFEFF0700FFFFFEFF01000100FBFFFBFF010001000300FEFF0000FDFFFEFFFFFF040000000100FEFFF9FF01000300FEFFFEFFFEFFFBFFF9FFFAFF0300020004000300FBFF0200FFFF0500010001000400FEFF030002000400FFFFFDFFFFFF01000100000001000100FEFFFEFFFAFFFFFF0500FCFF0200FEFFF8FFFAFF0300FEFF0600FFFF0000FDFFFCFF0200000001000100050001000100FDFFFCFF0100FEFF03000400FEFF0000FBFF00000000FFFFFDFF0300FAFF0200FFFFFFFFFCFFFFFF01000400FCFFFFFF03000100FCFF0000FEFF01000100F8FFFFFFF8FFFBFFFDFFFBFF0100FEFFFFFF000001000200010005000400FCFFFCFF0000FFFFFFFF000001000300FEFFF5FFFEFFFEFFFDFFFEFFFEFF0000FCFFFFFF00000000FBFFFDFFFFFFFBFF000007000000FBFF040000000200FFFF04000300FFFFFBFFFFFF0200FDFFFFFFFFFF020000000000FDFFFFFF0000F9FF0000FCFF010001000000FFFF020001000300FFFF030002000100FFFFFCFFFDFF000001000300FEFF03000200FFFFFDFFFFFFFEFF01000100FFFFFFFFFFFF0200030000000000FFFF03000500FFFFF8FF0300FEFF000002000100FBFFFDFFFDFF0100F8FFFBFF0100FDFFFCFFFDFF02000200FCFFFFFFFFFFFEFF0500FEFFFFFF00000200FBFF000000000600FFFFFDFFFFFF0000010000000100FFFFFCFFFBFFFFFFFEFFFEFFFFFFFFFFFDFF07000200FFFF020001000000FFFFFEFF03000500000003000200FBFF0200FFFFFFFF02000500010000000200FFFFFBFF0000FEFF0200FEFF0000020003000100FFFF00000500FEFFFCFF0400FCFF0000FDFFFFFF04000200FFFF0100FFFF0500000005000200FDFF0200FFFF000001000500040000000400FFFFFBFFFEFFFAFF00000100FEFFFFFF0600000003000100FEFF04000400040000000000FDFF04000000FEFF0500FDFFFFFFFDFF0100FCFF010000000300FDFFFEFFFFFF030000000100FEFF0000FAFFFDFF0100FFFF0100FEFF000000000500020000000000FCFFFFFF000001000000FFFF00000200FFFFFEFFFCFFFEFF0100FFFFFEFF030000000600020005000100FFFF040000000000FFFF000001000500FFFF000003000600FFFFFEFFF9FF0000FDFFFEFF050004000000FCFF0300FBFF010004000100030001000000FCFF0100FFFF00000300010001000300FFFFFDFF0200FCFFFCFF01000300FDFF0400FFFFFDFF020002000400FEFF0200FFFF01000100040001000200FFFF0200050000000100FDFF02000600FFFF000004000100FFFFFFFF000000000100FAFFFCFFFFFF01000100FBFF0200FBFF01000300FEFFFDFF000000000000FDFF0000FFFF04000300FFFFFFFF01000100FCFFFDFFFFFFFFFFFCFF00000200FDFF01000200010000000400FEFFFEFFFCFF01000200FDFF01000100FFFF0500FBFF010002000000FDFFFFFF030001000400020000000000010000000400010003000100FEFF0500FFFFFDFF0200FAFF01000200FFFF0400030006000000FFFFFFFF02000300FBFF0800000004000000FEFFFDFFFEFF04000300020000000000FEFF0300FCFF030003000100FDFF0200010000000200FEFFFCFF0200FEFF01000100FDFF00000300FDFF000006000300FFFF0000FDFF00000100FFFFFFFF01000100020000000000FBFF0100FEFF03000100FDFF0400FEFF0100FFFF0200FDFF0200FCFFF9FFFEFFFEFFFBFF0100FDFFFDFFFBFFFFFFFCFFFCFF0100FFFF000001000000FFFF02000000F9FFFBFF00000400FCFF0000FDFFFFFFFBFF0300FEFF0100FFFF02000100010000000200FDFFFFFFFCFFFEFFFCFF03000100FAFF030000000000FDFF0400FCFFFFFF000000000200FDFF0100FEFF0100FAFFFEFF02000100FFFF0500FCFFFCFF04000200000001000200020000000200FFFFFBFF0200FBFFFEFF0200FFFFFBFFFEFFFEFF0300000000000200FFFF0000FEFF0500FDFFFFFFFDFFFEFF0000FDFF0200FEFFFFFFFAFFFDFF0100FFFF0100F9FFFDFF03000100FDFF0200FFFF0000FFFFFFFFFFFFFDFFFCFF020001000000FFFFFEFF0600FFFF020009000000FFFFFFFF0400FEFF0100040001000200FFFFF9FFFDFFFDFFFCFF020002000400010000000300040000000100FFFFFEFFF9FFFCFFFCFF02000000FDFFFEFFFFFF0600FEFF04000500020003000200FFFFFCFFFDFF00000400F9FF0100FFFF000004000100000001000100FAFFFCFF0100FCFFFDFF0200020002000000FFFFFEFF0200000000000200FFFF0200FEFF0100FDFFFFFFFFFF0200FFFF01000200FEFFFEFFFDFFFFFF0000F9FF020001000100FFFFFBFF00000400FFFFFEFF000001000200FFFF0400FDFFFEFFFEFF02000100FEFF00000000FFFF010000000200FDFFFCFFFAFFFDFFFDFF00000000FDFF0200000001000100FBFFFEFFFEFF020002000100FFFFFFFF01000200F9FFFDFF050003000000FBFF040002000200FDFF0300010000000300FDFF0100FDFF00000300FEFFFEFFFDFFFFFF0500FCFF01000000FDFFFDFF040003000100FEFFFCFFFEFF0000FCFF020000000200FDFF06000200040004000100FCFFFFFFFEFFFFFF03000000FFFF010006000000050001000400FFFF0100FBFF000000000200FDFFFCFF00000200FEFF020001000200030000000000FDFFFCFF000002000300FEFF06000000FDFFFBFF0200FCFF0000FFFFFDFFFDFF0000FDFF02000200030001000000FDFF0300FFFF00000500FBFF04000200FFFF040001000100FEFF0300FAFF0200FDFFFEFFFBFFFDFF000000000200FBFF03000000040000000100000000000000000000000800000005000000FEFF020003000400FDFF010001000000FEFFFDFFFEFFFBFF02000300FEFFFEFFFCFF0100050005000000FEFF0300FDFF00000500010000000100FFFFFEFFFEFF000002000200FCFFFFFF00000300FFFFFEFFFDFF0000FFFF00000100FFFF020000000400FFFF060001000000020002000600FDFF0100FDFFFFFFFDFFFCFF050000000000020001000000F8FFFEFF0000FDFFFDFF000001000000FDFF02000600FAFF010002000300FCFF0100FCFF0200FAFFFEFF040001000000020000000100000004000200FEFF020002000300FFFF01000000FEFFFCFFFFFF04000300000002000200FEFF0000FEFF0200FDFFFDFF02000300FEFFFFFF0200FFFFF9FF0300FDFF0300010007000000FFFF050002000000FDFF03000200000002000300FFFF02000000FFFFFEFF000000000200FDFFFDFF0200010002000100FFFF04000000FDFF0100FFFFFCFF0200FCFF01000000FFFFFFFF0100FEFFFEFFFDFFFFFFFDFF0000FFFFFFFF0000FEFFFCFF0000FFFF0000FCFFFDFF01000000FFFF00000400000001000000FDFF0000FCFF00000000FEFFFDFFFFFF0000FFFFFBFF0200FFFF01000200FDFFFEFF03000000FDFFFDFFFEFFFFFF01000300FEFF02000400FDFFFDFFFEFFFEFF07000100FFFF0100FCFFFEFF05000300FEFFFEFF0100FFFFFFFF00000100030000000000FEFF0200FDFF0000FFFF0400FDFF000003000200010002000200FFFF0000F8FFFEFF000000000300FFFFFFFF0600FFFFFFFF0100FFFF02000200FDFF0100FBFF05000200FFFF040004000000FFFFFFFF02000200000000000100FCFF0200FFFFFDFF07000000FEFF0000FEFFF7FF0000FBFF0400FFFF04000300FEFFFAFFFCFF03000200FCFF0400FFFFFAFF0100FAFFFEFF060004000200FFFF02000300F9FF0100FEFF0400FEFF0500FCFFFFFFFEFFFBFFFAFFFFFF0400030003000100FDFF040001000300010001000000040002000200FFFFFBFFFDFFFFFF0200FFFF00000200FDFFFCFF0000FFFF0500030000000000FDFF000000000300FDFFFDFF04000200FFFFFFFFFFFFFFFF0000020007000000FEFFFFFF0200FAFF00000000FAFF010000000200FBFF000002000100FFFFFBFF0000040002000100FFFF010001000600FFFFFEFF0200FEFF030001000300FDFFFFFFFCFF0100FFFFFBFF0500FDFF00000300FCFFFDFFFBFF0400FEFFFEFF0200FEFFFFFFFFFFFEFF020002000000FFFF0000FCFFFFFFFEFFFFFF0000FCFFFDFF03000000FEFF06000500FDFF02000000000006000200000003000300FCFFFFFF0100FFFF0100FFFFFDFF02000200FDFFFFFF0000FFFF00000100FFFFFFFF01000500000004000100FCFF0400FEFF01000200FEFF000001000200020003000400FCFF000003000800FFFFFFFF0100FEFFFEFF05000000020002000200FEFF08000300FEFFFFFF05000300020001000200010004000300F9FFF9FF0000FDFF02000000FFFF0200FCFF010007000000F9FF0000FEFFFEFF0000010000000100FEFFFAFF0100030001000000020003000000FFFFFCFF030003000600FFFF01000200FCFF01000000FAFFFEFF0300000000000500040005000600FFFF000002000000000000000400040004000000FDFF020006000000FFFFFFFFFFFF0300FEFF01000100FEFF00000000FDFFFFFF0000FBFF0700FFFF0500FEFFFFFF00000400FEFF0000FFFF02000400FDFF0400000003000300FDFF020002000100020004000300FFFFFCFF0100FCFF01000000040000000200040000000000FEFFFEFF0000FAFFFFFFFCFFFDFF03000000FAFFFEFF0500FEFFFFFFFFFF0200FBFFFEFF0000FCFF0300FFFFFFFFFFFFFDFF07000700FEFFFDFF0000FCFF0300FBFFFDFF0200040004000000FCFFFDFF0400FFFF05000600FFFF03000300FDFF0100030000000200FFFF0200010005000000FEFF0200000001000300040002000000FBFFFFFF0400FEFFFFFFFFFFFEFFFFFF0100FBFF0200FBFF0300FFFFFEFFFFFFFEFF0100FBFFFFFF060002000000FFFF010004000100010004000200FFFF00000300FAFF0100FFFF01000400FDFFFEFFFFFF010004000300FDFF00000400FFFF0300FFFF00000100020003000300FDFFFDFF020001000000FFFFFDFF0100FCFF0200FFFF0000FEFF020001000200FCFF01000000FFFF02000600FFFFFEFF0300030002000000FFFFFDFF02000300FFFFFDFFFDFF0200FFFF00000200020005000300040005000000FCFFFFFF040003000000FFFF0000FBFFFFFF02000100FFFF000001000000FEFFFDFF030002000200FFFFFCFF010002000000FDFF00000500FBFFFEFFFEFFFFFF00000100FFFF0300FEFFFFFFFEFFFEFF0100FEFFFDFF0300FCFF010009000500FFFFFFFFFCFF0300FEFFFEFF050000000000060005000000FFFF000000000200FEFFFCFFFFFFFDFF02000100FDFF01000200FEFFFEFF02000400FCFFFFFF010005000300FFFF02000200020001000000FEFFFDFFFFFFFFFF04000100FCFF000000000300FDFFFEFF00000300000000000000FFFF040001000100FDFF0200FFFF020001000000030000000100FFFF0000FEFFFEFFFBFF0100FFFF04000300040000000100040001000000FDFFF8FF0100FFFFF9FF000002000200FDFF0400FFFFFCFF02000100FFFF0200040001000000FBFF0A00FEFFFBFFFCFF0100FEFFFFFFFFFF00000400FFFFFEFF01000300FEFF0100FEFFFDFF060001000000FCFF0000FFFFFFFFFCFF01000100FCFFFFFFFEFFFEFF0100030002000000FFFF0000FEFF010001000300020001000400FBFF0200FBFF01000100FDFFFDFFFDFFFFFFFDFF01000300FEFFFBFFFAFF010001000200FFFF00000200FFFFFEFFFFFF03000000FFFF0000FEFFFBFFFFFFFFFFFFFFFFFF0100FEFFFEFF02000200FDFFFFFFFFFF0100FFFF050000000000FCFFFDFFFFFF020002000200FEFFFFFF00000400FFFFFCFF07000100000004000400FFFF0100FFFF030003000200FEFFFBFF00000200FAFFFEFF0200010001000500FEFF000002000100FEFFFEFF0000FFFFFDFF05000100FDFFFEFF0100060004000400FCFFF9FFFDFFFFFFFEFF0600FDFF000001000500FFFFFEFFFDFF000000000500FEFF0400FFFF0200050000000300FEFF00000200FCFF01000100FDFF020001000000000001000000FFFF0500030001000400FCFFFEFFFDFFFEFFFEFFFDFFFDFFFCFFFBFF0200FFFFFCFF0300FAFF010002000100FCFFFFFF030004000100FEFF0100FDFFFDFF0100FEFFFCFFFCFF010003000000FEFF02000100FFFFFFFF0400000000000000FBFF01000400FDFFF9FF0200FEFF0100FCFF03000000010002000600FDFF0100FDFFFEFFFFFF01000300020007000400FEFF0000FCFF0400FEFFFFFFFEFF000001000200FCFF0300020001000200000001000000FBFFFEFFFEFF0500FDFFFFFF01000300FDFFFEFFFEFF0100FDFF00000400FFFFFEFF02000500FFFF0100FBFFFCFFFCFF0100FDFF0100FFFFFEFF020000000200FCFF0100F9FF0100FEFF030002000300040000000000FFFF0500000004000200FBFFFCFF050004000700000001000100FDFF0100FCFF00000300FFFF0000FFFFFAFF0100FEFF0600FEFFFEFF0300FFFF0500FEFF0000FFFF02000200FEFFFFFF0400FEFF020001000200FDFFFDFF04000300FCFF0200FDFF0200FAFF05000100FFFFFBFFFFFFFDFFFEFF03000000FAFF0300FEFFFEFF0200FFFFFFFF0100FFFFFCFFFCFF000005000200FCFFFBFFFFFFFDFFFEFFFFFF000000000100FDFF00000200FFFF0200FFFF0100FEFFFEFF0000FDFF0600FDFFFFFFFEFFFEFF00000100FEFF0100FCFFFCFFFDFFFDFF0400040000000400FFFFFEFF0300FDFFFDFFFDFFFFFFFFFF0200FBFFF9FF0000FFFF02000200000002000300FFFFFBFFFDFF0000FEFFFFFF000004000000FFFF0400FDFF0500FDFFFCFFFBFF00000400FEFFFFFF01000100FDFF020000000400FEFFFFFFFAFF03000100FAFFFFFFFCFF020002000100FEFFFFFFFDFF0100FFFF01000000010002000300FCFFFCFFFEFFFFFFFFFFFEFF020001000200FEFFFEFFFEFFFEFF0100FEFF0200FBFFFDFF0400FBFF000000000300FBFFFDFF01000000FDFF0100070003000300FEFF0100FDFF010004000100FCFFFFFFFEFFFEFFFEFF0300030002000200010002000500FCFF01000200FDFFFFFF0100FDFF0200FDFFF8FF020003000100FEFFFDFFFCFF0000FEFFFEFFFCFF0400010002000300FDFFFEFF030004000200FEFFFCFFFEFF00000200FFFF0000030001000000FDFF0200FDFF010000000100FEFFFFFF00000300010002000000FFFF0300FEFF0100FFFFF8FFFCFF000001000000FDFF0200FFFF040003000000FFFF00000100FFFF00000200020002000400FDFFFFFF01000100FFFFFCFF0500FCFF0100FFFFFFFF0000FDFFFFFF0000FBFF0100F9FF0300F9FFFDFF0000FAFFFDFF0400020003000200FEFF040000000500FFFFFFFFFEFFFEFFFFFF010002000300FDFFFFFF0000FCFF04000000FEFFFCFFFDFF000003000100FEFFFFFF0000FDFFFFFF0400FFFF00000100FEFF0000FDFF0000FEFF0300FFFF0000FEFF00000000F8FFFDFF02000100FFFF0200FDFF0000FFFFFFFFFFFFFEFFFCFF0200FFFFFEFF00000200020000000600FDFFFFFF010001000000FCFF0400FFFFFFFF0000010002000100FFFFFDFFFBFF0200FDFFFDFF00000300FBFFFAFF00000200000000000200FFFF0200FAFF05000100FDFF00000100FEFF03000100FCFF05000400FEFF0000FEFF0A00FDFF03000000FDFF04000300FBFF050000000000FDFF0300FFFF0100020002000300030001000300FEFF0000000002000100040005000200FFFF0000030001000000030001000500030001000100010005000100FDFF0400FFFFFBFFFFFF020004000300FFFF020000000000010002000100FFFF010000000000FFFFFFFFFDFFFEFFFFFFFFFFFFFF03000100FCFFFDFFFFFFFFFFFFFFFDFFFEFFFCFF0300FDFFFEFFFFFF0500FFFFFFFF0100FEFF010000000000FFFF020002000300020005000100FDFF00000200FFFFFBFF00000500FFFF030000000200FDFF0100FDFFFFFF0400FCFF000005000000FDFF020000000100FCFF0400FFFFF9FFFFFFFFFF020002000300030000000100FFFF02000000FDFFFFFFFFFF0100FEFF0300FEFFFCFF000001000100FBFFFDFFFEFF0100000005000300FEFF0100FEFF0500FAFFFFFF03000100010001000100FCFF0300000005000600FFFF0000FEFFFCFF0000FAFFFFFFFBFF0300FFFF04000300FEFFFEFF00000400FDFFFEFFFCFF0400F8FFFDFF00000000000000000000FEFF0100040002000200FEFFFFFFFCFF00000000FEFF01000200FFFFFDFFFCFF0300FCFF0400FDFF0000FEFFFBFFFAFF0300FDFF05000600000000000200000003000300FEFFFEFFFFFF0100FEFFFFFF000004000400020000000400010002000000FFFFF9FFFEFF0400FDFF0100FAFF0300FDFFFBFFFFFF0100030005000000FCFFFDFF0100FCFF01000100FFFF0200FFFF03000000FEFFFFFF0000FFFF0100FEFF0000000002000000030001000500060005000100FBFF02000000FFFF00000300000000000400FEFF040001000200FBFF000001000200FDFF0100F9FF05000000FEFFFAFFFFFFFFFF060004000200FCFFFEFFFCFF0200FDFF01000000FDFFFEFFFEFFFAFF0200FDFFFEFFFFFF04000100FFFF0200FFFFFFFF05000200FEFFFCFF03000200FFFF0200FDFFFEFF0000FBFF0100FEFF010001000000FDFFFFFF0200FDFFFDFF0000FEFFFFFFFEFF02000000FCFF00000200FDFF0500FDFFFFFFFFFFFEFFFFFF000003000100000003000500FFFF0000FBFFFDFF0200010001000200FCFFFEFF0400FFFF01000000010001000000FFFFF9FF00000000030000000600FDFF0100FFFFFFFFFCFF0000FDFFFDFF020003000400FEFFFFFF0200FFFFFFFF0100FFFF000000000200FFFFFFFF02000500FCFF01000000FEFFFCFF0100FDFFFCFF03000100FEFFFDFFFCFF0200FFFFFDFF02000200FCFF0400020001000400FCFF0100FCFF02000400FCFF01000200FAFF020002000700FCFF0300FDFFFEFFFFFF0300FEFF0800FFFFFEFF0100FFFF0100FCFFFFFFFCFFFCFFFEFFFFFF020002000400030005000100FFFFFCFF0200FEFF0200FEFF0900000000000200FEFF0100FBFF0300FEFF020004000300FFFFFEFF0100010001000300010004000200FEFFFEFF0300030000000100FFFFFEFF00000500FFFF0300FDFF01000000000002000300FAFFFFFFFCFF0200FDFFFEFFFCFFFDFF0000FFFF00000000FFFF0200FFFF02000300FDFF02000500FFFFFDFF00000200FEFFFDFFFEFF0000010005000100FBFF0000FFFF01000100FEFF0300010003000000030001000600FDFFFEFFFFFF020000000500FCFFFEFF0800FFFF03000000FDFFFFFF0300FEFF07000200020003000400FFFF0400000002000400FDFFFEFFFFFF01000100FEFFFCFF03000500FEFF0400FEFFFFFF010003000000000001000300050003000200FEFF0100FDFF0100040000000400010003000200020002000100FEFFFBFF0100FEFFFFFF0200060001000700FFFF04000000FFFFFBFF0100FEFFFEFF01000100FFFF050000000000FAFF03000200FDFF010001000200FDFFFDFFF8FFFBFF04000300FEFFFCFF01000100FCFFFEFF0200020004000400FEFF03000000FFFFFEFF040000000300FFFFFBFFFFFFFAFFFFFF010001000200FEFF0400FCFFFDFF0100020003000600FDFFFBFF0500FAFF00000100FEFFFDFF01000000FCFFFCFF08000100FFFF030004000000FDFF030002000200FCFF000000000200FAFFFFFF040003000300FFFFFDFFFBFFFFFFFCFFFFFFFEFFFEFF01000100FFFFFFFF0400FFFF0300000002000400FEFFFCFF0400FFFFFFFFFFFFFDFFFBFF04000400FBFF0000FCFF0100FFFF02000200FDFF030001000500050001000300FDFFFFFFFEFF040000000000FBFFFCFFFDFF020001000100FFFF000002000000FBFFFCFF01000500FEFFFFFFFBFFFDFFFCFF0200FDFF010002000100FCFFFFFFFDFF0000FDFFFFFF03000400010005000200F9FFFEFF0100FCFF05000000FBFF040001000000FFFF0300FEFFFEFF0200FCFF0300FAFF040002000400FFFF010001000500FEFFFFFF0200FDFF0300020001000200030001000400FFFF0100030000000500FBFF0300FCFFFEFFFEFFFEFF05000800FDFF03000400000003000400010003000000FCFFFBFFFCFF0100FCFF0100FBFFFEFF01000400FEFF02000100010000000200040001000100FDFF0000040003000100FFFFFBFF040000000500FFFFFDFF00000000FCFF020004000300FFFF0400FCFFFFFFFFFFFFFFFEFF06000500FEFFFDFFFFFF02000200FDFF0100FFFF0000FFFF0000FFFF0200FDFFFEFF00000300020002000100F9FFFCFFFEFF0100FDFF0000000000000200050000000200FFFF0000010000000000FFFFFCFFF9FFFFFF03000400FAFF07000100030001000000FEFFFDFFFEFFFBFFFFFFFEFFFBFF01000500FBFF0000FCFF0100FEFF030001000400FDFF00000100000000000000FEFF010000000000F9FF0000FDFFFDFF0200FAFF0000FFFFFEFF0300FEFF03000000FDFF0400FFFF01000000FDFF01000600020003000600040003000200010000000100FDFF0100FCFF0100FEFF0000FDFFFFFFFEFFFFFF0300FAFF0200020001000100040001000000FDFFFDFF0000FBFF01000000FCFFFCFF0300FEFF020006000300FFFF01000300FEFF00000400040001000000FFFF0200000000000000030000000100020000000000FCFFF9FFFFFF010001000100FFFFFCFF0000FCFFFCFFFFFF0200FFFF0100FFFF0400FEFF01000000FCFF0400010001000200FFFF010002000200FCFFFEFFFDFFFFFFFBFF01000100FEFFFDFFFAFF00000000FCFFFEFFFDFF0100FDFF000002000300FCFFF9FF0000FEFF0100030003000000FEFF02000500FFFF02000000FEFFFFFF01000000FEFFFDFFFEFF010001000000000001000100FDFF010005000200FEFF0500040000000100FFFF0100FCFF04000100FEFFFCFF0200030003000400FFFFFFFF0000FBFF0500FFFFFFFF01000100FEFFFEFFFFFF010004000000000000000100FDFF0000FCFF0000010003000300FEFF04000200FFFF01000000FCFF0300FCFF04000000030000000100020006000000FDFFFFFFFEFF08000200FDFF01000400FDFFFFFF0100FDFFFDFF0100FBFF03000100FEFF00000100010001000100FDFF020000000500FAFF01000200FCFF0000FEFF0500F9FF020005000100FEFF0000040002000300FDFFFFFFFCFF01000300020002000000FCFFFEFFFEFF01000100FEFF0000FDFF0100FFFF000001000400FFFF0000FEFFFCFFFFFFFEFFFCFFFFFFFFFF0500FFFF0000FFFF010002000000FDFFFAFFFEFF030000000000FFFF00000100F9FFFAFFFEFFFFFFFEFF0200FFFF0200FFFFFEFF02000000FFFF00000300FFFFFFFFFFFF00000200FCFF0000FDFFFBFF0000F9FF0100FCFFFDFF0000FFFFFDFF0300FFFF0100FEFF0300FEFF00000100000001000100FDFFFFFFFCFFFFFF010001000300FFFFFFFFFFFF0400FDFFFEFFFDFFFCFF01000400020000000000FBFF05000200030000000100020001000000FDFF00000100FEFFFFFF01000000FDFF0100FFFF000000000100FFFF0100FEFFFEFF0100FFFF050001000000030001000000FEFF0700FEFFFDFFFFFFFDFFFEFFFFFF0300FFFF030002000000FBFF04000000FFFF000003000200FFFFFFFFFFFF0300FFFF0400FFFF03000300FEFFFFFFFBFF0200FFFFFFFF0000FDFFFFFF02000000D598BDDCFC42A0D3EC682C784A0587F7",
    //   "expiryDate": "02/09/2020 18:10:38",
    //   "checkSum": "39776"
    // }
    tIB_OOBDATA *pOobData = (tIB_OOBDATA *)malloc(sizeof(tIB_OOBDATA));
    if (!szJsonString)
    {
        app_tracef("ERROR: Failed to allocate %u bytes for OOB Data", sizeof(tIB_OOBDATA));
        return 2083;
    }
    bool success = __ParseJsonOOBData(szJsonString, pOobData);
    if (!success)
    {
        app_tracef("ERROR: Failed to parse OOB json string");
        free(pOobData);
        pOobData = NULL;
        return 2084;
    }

    tLSTRING binaryData = {0U, NULL};
    success = decodeHexLString(&(pOobData->hexData), &binaryData);
    if (!success)
    {
        app_tracef("ERROR: Failed to decode KEM secret key hex string");
        free(pOobData);
        pOobData = NULL;
        return 2085;
    }

    rc = WriteToFile(pIBRand->ourKemSecretKeyFilename, &binaryData, true);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to write KEM secret key to file \"%s\"", pIBRand->ourKemSecretKeyFilename);
        free(binaryData.pData);
        binaryData.pData = NULL;
        binaryData.cbData = 0;
        free(pOobData);
        pOobData = NULL;
        return rc;
    }
    free(binaryData.pData);
    binaryData.pData = NULL;
    binaryData.cbData = 0;
    free(pOobData);
    pOobData = NULL;
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
static bool __ParseJsonOOBData(const char *szJsonString, tIB_OOBDATA *pOobData)
{
    JSONObject *json2 = NULL;
    const int localConfigTracing = false;

    json2 = my_parseJSON(szJsonString);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse OOB JSON string\n");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localConfigTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s\r\n", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");

        if (json2->pairs[ii].type == JSON_STRING)
        {
            if (strcmp(json2->pairs[ii].key,"requiredSegments")==0)
            {
                pOobData->requiredSegments = atoi(json2->pairs[ii].value->stringValue);
            }
            else if (strcmp(json2->pairs[ii].key,"segmentNumber")==0)
            {
                pOobData->segmentNumber = atoi(json2->pairs[ii].value->stringValue);
            }
            else if (strcmp(json2->pairs[ii].key,"hexData")==0)
            {
                // json2->pairs[ii].value->stringValue is a malloc'd zstring which will be freed later in my_freeJSONFromMemory(), so we must duplicate here
                // Essentially, a strdup...
                size_t buffer_size = strlen(json2->pairs[ii].value->stringValue)+1;
                pOobData->hexData.pData = malloc(buffer_size);
                if (!pOobData->hexData.pData)
                {
                    app_tracef("ERROR: Failed to allocate %u bytes for pOobData->hexData", buffer_size);
                    return false;
                }
                my_strlcpy(pOobData->hexData.pData, json2->pairs[ii].value->stringValue, buffer_size);
                pOobData->hexData.cbData = buffer_size;
            }
            else if (strcmp(json2->pairs[ii].key,"expiryDate")==0)
            {
                // json2->pairs[ii].value->stringValue is a malloc'd zstring which will be freed later in my_freeJSONFromMemory(), so we must duplicate here
                // Essentially, a strdup...
                size_t buffer_size = strlen(json2->pairs[ii].value->stringValue)+1;
                pOobData->expiryDate.pData = malloc(buffer_size);
                if (!pOobData->expiryDate.pData)
                {
                    app_tracef("ERROR: Failed to allocate %u bytes for pOobData->expiryDate", buffer_size);
                    return false;
                }
                my_strlcpy(pOobData->expiryDate.pData, json2->pairs[ii].value->stringValue, buffer_size);
                pOobData->expiryDate.cbData = buffer_size;
            }
            else if (strcmp(json2->pairs[ii].key,"checkSum")==0)
            {
                pOobData->checkSum = atoi(json2->pairs[ii].value->stringValue);
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}


static void PrintConfig(tIB_INSTANCEDATA *pIBRand)
{
    // Hide the password against wandering eyes
    char hiddenPassword[32];

    memset(hiddenPassword, 0, sizeof(hiddenPassword));
    for (int ii=0; ii<my_minimum(sizeof(hiddenPassword)-1,strlen(pIBRand->szPassword)); ii++)
       hiddenPassword[ii] = '*';

    app_tracef("szAuthType            =[%s]" , pIBRand->szAuthType            ); // char          szAuthType               [16]   // "SIMPLE";
    app_tracef("szAuthUrl             =[%s]" , pIBRand->szAuthUrl             ); // char          szAuthUrl                [128]  // "https://ironbridgeapi.com/login";
    app_tracef("szUsername            =[%s]" , pIBRand->szUsername            ); // char          szUsername               [32]
    app_tracef("szPassword            =[%s]" , hiddenPassword                 ); // char          szPassword               [32]
    app_tracef("szAuthSSLCertFile     =[%s]" , pIBRand->szAuthSSLCertFile     ); // char          szAuthSSLCertFile        [128]  // "/etc/ssl/certs/client_cert.pem"
    app_tracef("szAuthSSLCertType     =[%s]" , pIBRand->szAuthSSLCertType     ); // char          szAuthSSLCertType        [32]   // "PEM"
    app_tracef("szAuthSSLKeyFile      =[%s]" , pIBRand->szAuthSSLKeyFile      ); // char          szAuthSSLKeyFile         [128]  // "/etc/ssl/private/client_key.pem"
    app_tracef("authRetryDelay        =[%d]" , pIBRand->authRetryDelay        ); // int           authRetryDelay
    //app_tracef("ourKemSecretKey       =[%s]" , hiddenKemSecretKey             );
    //app_tracef("theirSigningPublicKey =[%s]" , pIBRand->theirSigningPublicKey );
    app_tracef("useSecureRng          =[%u]" , pIBRand->useSecureRng          );
    app_tracef("szBaseUrl             =[%s]" , pIBRand->szBaseUrl             ); // char          szBaseUrl                [128]  // "https://ironbridgeapi.com/api"; // http://192.168.9.128:6502/v1/ironbridge/api
    app_tracef("bytesPerRequest       =[%d]" , pIBRand->bytesPerRequest       ); // int           bytesPerRequest                 // 16
    app_tracef("retrievalRetryDelay   =[%d]" , pIBRand->retrievalRetryDelay   ); // int           retrievalRetryDelay             //
    app_tracef("szStorageType         =[%s]" , pIBRand->szStorageType         ); // char          szStorageType            [16]   // "FILE";
    app_tracef("szStorageDataFormat   =[%s]" , pIBRand->szStorageDataFormat   ); // char          szStorageDataFormat      [16]   // RAW, BASE64, HEX
    app_tracef("szStorageFilename     =[%s]" , pIBRand->szStorageFilename     ); // char          szStorageFilename        [128]  // "/var/lib/ibrand/ibrand_data.bin";
    app_tracef("szStorageLockfilePath =[%s]" , pIBRand->szStorageLockfilePath ); // char          szStorageLockfilePath    [128]  // "/tmp";
    app_tracef("storageHighWaterMark  =[%ld]", pIBRand->storageHighWaterMark  ); // long          storageHighWaterMark            // 1038336; // 1MB
    app_tracef("storageLowWaterMark   =[%ld]", pIBRand->storageLowWaterMark   ); // long          storageLowWaterMark             // 102400; // 100KB
    app_tracef("idleDelay             =[%d]" , pIBRand->idleDelay             ); // int           idleDelay                       //
    app_tracef("fVerbose              =[%u]" , pIBRand->fVerbose              ); // unsigned char fVerbose                        // bit 0=general, bit1=auth, bit2=data, bit3=curl:
}

int main(int argc, char * argv[])
{
    // Our process ID and Session ID
#ifdef RUN_AS_DAEMON
    pid_t processId = {0};
    pid_t sessionId = {0};
#endif // RUN_AS_DAEMON
    int rc;
    tIB_INSTANCEDATA *pIBRand;


    // =========================================================================
    // Create instance storage
    // =========================================================================
    pIBRand = malloc(sizeof(tIB_INSTANCEDATA));
    if (!pIBRand)
    {
        fprintf(stderr, "FATAL: Failed to allocate memory for local storage. Aborting.");
        exit(EXIT_FAILURE);
    }
    memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));

    // =========================================================================
    // And they're off!!!
    // =========================================================================
    fprintf(stdout, "IronBridge(tm) IBRand Service v0.40\n");
    fprintf(stdout, "Copyright (c) 2020 Cambridge Quantum Computing Limited. All rights reserved.\n");
    fprintf(stdout, "\n");

    if ((argc > 2) && strcmp(argv[1],"-f")==0)
    {
        my_strlcpy(pIBRand->szConfigFilename, argv[2], sizeof(pIBRand->szConfigFilename));
    }
    else
    {
        char *tempPtr;
        rc = my_getFilenameFromEnvVar("IBRAND_CONF", &tempPtr);
        if (rc==0)
        {
            my_strlcpy(pIBRand->szConfigFilename, tempPtr, sizeof(pIBRand->szConfigFilename));
            free(tempPtr);
        }
    }

    if (strlen(pIBRand->szConfigFilename) == 0)
    {
        fprintf(stderr, "FATAL: Configuration not specified, neither on commandline nor via an environment variable.\n");
        fprintf(stderr, "USAGE: ibrand_service [-f <ConfigFilename>]\n");
        fprintf(stderr, "       If <ConfigFilename> is NOT specified on the command line,\n");
        fprintf(stderr, "       then it must be specified in envar \"IBRAND_CONF\".\n");
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef RUN_AS_DAEMON
    app_trace_openlog("ibrand_service", LOG_PID, LOG_DAEMON);
#else // RUN_AS_DAEMON
    app_trace_openlog("ibrand_service", LOG_PID|LOG_CONS|LOG_PERROR, LOG_USER );
#endif // RUN_AS_DAEMON

    rc = ReadConfig(pIBRand->szConfigFilename, pIBRand);
    if (rc != 0)
    {
        fprintf(stderr, "FATAL: Configuration error. rc=%d\n", rc);
        app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef RUN_AS_DAEMON
    // Fork off the parent process
    processId = fork();
    if (processId < 0)
    {
        fprintf(stderr, "FATAL: Failed to create child process\n");
        app_tracef("FATAL: Failed to create child process. Aborting.");
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }
    // If we got a good pid, then we can exit the parent process.
    if (processId > 0)
    {
        /////////////////////////////////////////
        // We are the parent process
        /////////////////////////////////////////
        fprintf(stdout, "INFO: IBRand Service started successfully (pid:%u)\n", processId);
        if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
            app_tracef("INFO: IBRand Service started successfully (pid:%u)", processId);
        app_trace_closelog();
        exit(EXIT_SUCCESS);
    }

    /////////////////////////////////////////
    // We are the child process
    /////////////////////////////////////////

    processId = getpid(); // was, by definition, 0
    app_tracef("INFO: CQC IronBridge IBRand Service Started Successfully (pid:%u)====================", processId);

    // Change the file mode mask
    umask(0);

    // Open any logs here

    // Create a new SID for the child process
    sessionId = setsid();
    if (sessionId < 0)
    {
        app_tracef("FATAL: Failed to create a new SID for the child process. Aborting.");
        // Log the failure
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

    // Change the current working directory
    if ((chdir("/")) < 0)
    {
        // Log the failure
        app_tracef("FATAL: Chdir failed. Aborting");
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef FORCE_ALL_LOGGING_ON
    SET_BIT(pIBRand->fVerbose, DBGBIT_STATUS );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CONFIG );
    SET_BIT(pIBRand->fVerbose, DBGBIT_AUTH   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_DATA   );
    SET_BIT(pIBRand->fVerbose, DBGBIT_CURL   );
    // Leave the standard file descriptors open
#else // FORCE_ALL_LOGGING_ON
    // Close out the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif // FORCE_ALL_LOGGING_ON

#else // RUN_AS_DAEMON
    app_tracef("INFO: CQC IronBridge IBRand Process Started Successfully ====================");
#endif // RUN_AS_DAEMON

    // =========================================================================
    // Daemon-specific initialization
    // =========================================================================

    // =========================================================================
    // Main loop
    // =========================================================================

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CONFIG))
    {
        PrintConfig(pIBRand);
    }

    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: Running");

    unsigned long numberOfAuthSuccesses =  0;
    unsigned long numberOfAuthFailures =  0;
    unsigned long numberOfConsecutiveAuthFailures =  0;

    unsigned long numberOfRetreivalSuccesses =  0;
    unsigned long numberOfRetreivalFailures =  0;
    unsigned long numberOfConsecutiveRetreivalFailures =  0;

    pIBRand->ResultantData.pData = NULL;
    pIBRand->ResultantData.cbData = 0;
    pIBRand->isPaused = false;

    // Ensure that we don't still have a lock file from a previous run
    my_releaseFileLock(pIBRand->szStorageLockfilePath, pIBRand->szStorageFilename, FILELOCK_LOGLEVEL);

    tSERVICESTATE currentState = STATE_START;
    bool continueInMainLoop = true;
    bool printProgressToSyslog = true;
    // The Big Loop
    while (continueInMainLoop)
    {
        if (printProgressToSyslog)
        {
            if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
            {
                app_tracef("INFO: Stats("
                                "AUTH(S%lu,F%lu,f%lu),"
                                "RNG(S%lu,F%lu,f%lu),"
                                "STORE(%s,N%ld))",
                                numberOfAuthSuccesses, numberOfAuthFailures, numberOfConsecutiveAuthFailures,
                                numberOfRetreivalSuccesses, numberOfRetreivalFailures, numberOfConsecutiveRetreivalFailures,
                                pIBRand->isPaused?"Draining":"Filling ", pIBRand->datastoreFilesize);
            }
            printProgressToSyslog = false;
        }
        switch (currentState)
        {
            case STATE_START:
                currentState = STATE_INITIALISECURL;
                continue;

            case STATE_INITIALISECURL:
                if (pIBRand->fCurlInitialised)
                {
                    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
                        app_tracef("INFO: Already initialised");
                    currentState = STATE_AUTHENTICATE;
                    continue;
                }
                rc = InitialiseCurl(pIBRand);
                if (rc != 0)
                {
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: InitialiseCurl failed with rc=%d. Will retry initialisation in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    currentState = STATE_INITIALISECURL;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: InitialiseCurl failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
                    app_tracef("INFO: Curl Initialisation OK");
                currentState = STATE_AUTHENTICATE;
                break;

            case STATE_AUTHENTICATE:
                printProgressToSyslog = true;
                if (pIBRand->fAuthenticated)
                {
                    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CURL))
                        app_tracef("INFO: Already authenticated");
                    currentState = STATE_GETNEWSHAREDSECRET;
                    continue;
                }
                rc = DoAuthentication(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
    #ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: DoAuthentication failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    currentState = STATE_AUTHENTICATE;
    #else // RUN_AS_DAEMON
                    app_tracef("ERROR: DoAuthentication failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
    #endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Authentication OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_GETNEWSHAREDSECRET;
                break;

            case STATE_GETNEWKEMKEYPAIR:
                printProgressToSyslog = true;
                // Request a new KEM secret key
                rc = getNewKemKeyPair(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: getNewKemKeyPair failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    currentState = STATE_GETNEWKEMKEYPAIR;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: getNewKemKeyPair failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                currentState = STATE_DECRYPTKEMSECRETKEY;
                break;

            case STATE_DECRYPTKEMSECRETKEY:
                // Do we have an encryptedKemSecretKey ?
                if (pIBRand->encryptedKemSecretKey.pData == NULL)
                {
                    currentState = STATE_GETNEWKEMKEYPAIR;
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Decrypting KEM secret key");
                int rc = DecryptAndStoreKemSecretKey(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: Decryption of KEM secret key failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    currentState = STATE_DECAPSULATESHAREDSECRET;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: Decryption of KEM secret key failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: KEM Secret key OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_GETNEWSHAREDSECRET;
                break;

            case STATE_GETNEWSHAREDSECRET:
                printProgressToSyslog = true;
                // Get SessionKey (aka SharedSecret)
                rc = getSecureRNGSessionKey(pIBRand);
                if (rc == ERC_OopsKemKeyPairExpired)
                {
                    currentState = STATE_GETNEWKEMKEYPAIR;
                    continue;
                }
                else if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: DoRequestSessionKey failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    currentState = STATE_GETNEWSHAREDSECRET;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: DoRequestSessionKey failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Encapsulated Session Key OK");
                currentState = STATE_DECAPSULATESHAREDSECRET;
                break;

            case STATE_DECAPSULATESHAREDSECRET:
                // Do we have an encapsulatedSessionKey ?
                if (pIBRand->encapsulatedSessionKey.pData == NULL)
                {
                    currentState = STATE_GETNEWSHAREDSECRET;
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Decapsulating session key");
                rc = DecapsulateAndStoreSessionKey(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Will retry in %d seconds", rc, pIBRand->authRetryDelay);
                    sleep(pIBRand->authRetryDelay);
                    currentState = STATE_DECAPSULATESHAREDSECRET;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Session key OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;

            case STATE_CHECKIFRANDOMNESSISREQUIRED:
                // Hysteresis
                pIBRand->datastoreFilesize = my_getFilesize(pIBRand->szStorageFilename);
                //app_tracef("DEBUG: Filename=\"%s\", Filesize=%d", pIBRand->szStorageFilename, pIBRand->datastoreFilesize);
                if (pIBRand->datastoreFilesize < 0) // File not found
                {
                    app_tracef("INFO: Bucket not found. Starting retrieval.", pIBRand->retrievalRetryDelay);
                    currentState = STATE_GETSOMERANDOMNESS;
                    continue;
                }
                if (pIBRand->isPaused) // We are waiting for the bucket to drain
                {
                    if (pIBRand->datastoreFilesize <= pIBRand->storageLowWaterMark) // Is it nearly empty
                    {
                        app_tracef("INFO: Low water mark reached. Starting retrieval.", pIBRand->retrievalRetryDelay);
                        pIBRand->isPaused = false;
                        currentState = STATE_GETSOMERANDOMNESS;
                        continue;
                    }
                    // Fall through to sleep
                }
                else // We are busy filling up the bucket
                {
                    // Does the bucket still have space?
                    if (pIBRand->datastoreFilesize < pIBRand->storageHighWaterMark)
                    {
                        // Yes... got some more randomness
                        currentState = STATE_GETSOMERANDOMNESS;
                        continue;
                    }
                    // No. The bucket is full.
                    app_tracef("INFO: High water mark reached. Pausing retrieval.", pIBRand->retrievalRetryDelay);
                    pIBRand->isPaused = true;
                    // Fall through to sleep
                }
                // Wait for a short while, and then try again
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_STATUS))
                    app_tracef("INFO: Idle. Sleeping for %d seconds", pIBRand->idleDelay);
                sleep(pIBRand->idleDelay);
                printProgressToSyslog = true;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;

            case STATE_GETSOMERANDOMNESS:
                printProgressToSyslog = true;
                // Get SessionKey (aka SharedSecret)
                if (pIBRand->symmetricSessionKey.pData == NULL)
                {
                    currentState = STATE_DECAPSULATESHAREDSECRET;
                    continue;
                }
                //////////////////////////////
                // Get the RNG material
                //////////////////////////////
                rc = getRandomBytes(pIBRand);
                if (rc == ERC_OopsSharedSecretExpired)
                {
                    currentState = STATE_DESTROYEXISTINGSHAREDSECRET;
                    continue;
                }
                else if (rc != 0)
                {
                    numberOfRetreivalFailures++;
                    numberOfConsecutiveRetreivalFailures++;
                    app_tracef("ERROR: %s Failed with rc=%d. Will try again in %d seconds", pIBRand->useSecureRng?"SRNG":"RNG", rc, pIBRand->retrievalRetryDelay);
                    sleep(pIBRand->retrievalRetryDelay);
                    currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                    continue;
                }
                else if (pIBRand->ResultantData.pData == NULL || pIBRand->ResultantData.cbData == 0 )
                {
                    numberOfRetreivalFailures++;
                    numberOfConsecutiveRetreivalFailures++;
                    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
                        app_tracef("WARNING: %s No data received. Will try again in %d seconds", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->retrievalRetryDelay);
                    sleep(pIBRand->retrievalRetryDelay);
                    currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                    continue;
                }
                currentState = STATE_STORERANDOMNESS;
                break;

            case STATE_STORERANDOMNESS:
                printProgressToSyslog = true;
                numberOfRetreivalSuccesses++;
                numberOfConsecutiveRetreivalFailures = 0;
                // pIBRand->ResultantData.pData must be freed by the caller
                storeRandomBytes(pIBRand);
                // Should be freed already, but just in case...
                if (pIBRand->ResultantData.pData)
                {
                    free(pIBRand->ResultantData.pData);
                    pIBRand->ResultantData.pData = NULL;
                }
                pIBRand->ResultantData.cbData = 0;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;

            case STATE_DESTROYEXISTINGSHAREDSECRET:
                if (TEST_BIT(pIBRand->fVerbose,DBGBIT_DATA))
                    app_tracef("INFO: %s Destroy sessionKey, forcing renewal", pIBRand->useSecureRng?"SRNG":"RNG");

                // Destroy any existing encapsulatedSessionKey, forcing the new one to be retrieved on next iteration on the main loop.
                if (pIBRand->encapsulatedSessionKey.pData)
                {
                    memset(pIBRand->encapsulatedSessionKey.pData, 0, pIBRand->encapsulatedSessionKey.cbData);
                    free(pIBRand->encapsulatedSessionKey.pData);
                    pIBRand->encapsulatedSessionKey.pData = NULL;
                    pIBRand->encapsulatedSessionKey.cbData = 0;
                }

                // Destroy any existing session key, forcing the new one to be decapsulated and used as and when needed.
                if (pIBRand->symmetricSessionKey.pData)
                {
                    memset(pIBRand->symmetricSessionKey.pData, 0, pIBRand->symmetricSessionKey.cbData);
                    free(pIBRand->symmetricSessionKey.pData);
                    pIBRand->symmetricSessionKey.pData = NULL;
                    pIBRand->symmetricSessionKey.cbData = 0;
                }
                currentState = STATE_GETNEWSHAREDSECRET;
                break;

            case STATE_SHUTDOWN:
                continueInMainLoop = false;
                break;
        }
    }

    ironbridge_api_finalise(pIBRand);

    app_tracef("WARNING: Terminating Service");
    app_trace_closelog();
    exit(EXIT_SUCCESS);
}
