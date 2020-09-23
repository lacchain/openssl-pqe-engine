///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// Based loosely on the service template provided by Devin Watson:
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

#include "ibrand_service.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_config.h"
#include "ibrand_service_datastore.h"

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

//#define HTTP_RESP_KEMKEYPAIREXPIRED    (426) // Upgrade Required
//#define HTTP_RESP_SHAREDSECRETEXPIRED  (424) // Failed Dependency (WebDAV)
//#define HTTP_RESP_PRECONDITIONFAILED   (412) // PreconditionFailed 412
#define HTTP_RESP_TOKENEXPIREDORINVALID  (498) // TokenExpiredOrInvalid 498
#define HTTP_RESP_KEMKEYPAIREXPIRED      (498) // TokenExpiredOrInvalid 498
#define HTTP_RESP_SHAREDSECRETEXPIRED    (498) // TokenExpiredOrInvalid 498

/////////////////////////////////////
// Forward declarations
/////////////////////////////////////
static int DecryptAndStoreKemSecretKey(tIB_INSTANCEDATA *pIBRand);
static int DecapsulateAndStoreSharedSecret(tIB_INSTANCEDATA *pIBRand);
static int ImportKemSecretKeyFromClientSetupOOBFile(tIB_INSTANCEDATA *pIBRand);

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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        app_tracef("INFO: Login: %u bytes received", cbNewData);

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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        app_tracef("INFO: rng request: %u bytes received", cbNewData);

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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        app_tracef("INFO: RequestNewKeyPair: %u bytes received", cbInboundEncryptedData);

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

    app_tracef("INFO: Symmetric encrypted payload received successfully (%lu bytes)", pIBRand->encryptedKemSecretKey.cbData);

    // Job done
    return cbInboundEncryptedData; // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_SharedSecret
// This is our CURLOPT_WRITEFUNCTION
// and userp is our encapsulatedSharedSecret
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_SharedSecret(char *buffer, size_t size, size_t nmemb, void *userp)
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
        app_tracef("ERROR: ReceiveDataHandler_SharedSecret() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        app_tracef("INFO: SharedSecret: %u bytes received", cbInboundKemData);

    // Free up the old buffer, if there is one
    if (pIBRand->encapsulatedSharedSecret.pData)
    {
        memset(pIBRand->encapsulatedSharedSecret.pData, 0, pIBRand->encapsulatedSharedSecret.cbData);
        free(pIBRand->encapsulatedSharedSecret.pData);
        pIBRand->encapsulatedSharedSecret.pData = NULL;
        pIBRand->encapsulatedSharedSecret.cbData = 0;
    }

    // Allocate a new buffer
    pIBRand->encapsulatedSharedSecret.pData = (char *)malloc(cbInboundKemData);
    if (pIBRand->encapsulatedSharedSecret.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound KEM data");
        return 0; // Zero bytes processed
    }
    memcpy(pIBRand->encapsulatedSharedSecret.pData, pInboundKemData, cbInboundKemData);
    // We will set the size once we know it has completed
    pIBRand->encapsulatedSharedSecret.cbData = cbInboundKemData;

    // Destroy any existing SharedSecret, forcing the new one to be decapsulated and used as and when needed.
    if (pIBRand->symmetricSharedSecret.pData)
    {
        memset(pIBRand->symmetricSharedSecret.pData, 0, pIBRand->symmetricSharedSecret.cbData);
        free(pIBRand->symmetricSharedSecret.pData);
        pIBRand->symmetricSharedSecret.pData = NULL;
        pIBRand->symmetricSharedSecret.cbData = 0;
    }

    app_tracef("INFO: KEM encrypted payload received successfully (%lu bytes)", pIBRand->encapsulatedSharedSecret.cbData);

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

    // Check that we have the sharedsecret needed for the decryption
    if (!pIBRand->symmetricSharedSecret.pData || pIBRand->symmetricSharedSecret.cbData <= 0)
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
    rc = AESDecryptBytes(rawEncryptedKey, decodeSize, (uint8_t *)pIBRand->symmetricSharedSecret.pData, pIBRand->symmetricSharedSecret.cbData, 32 /*saltsize*/, &pDecryptedData, &cbDecryptedData);
    if (rc)
    {
        printf("AESDecryptBytes failed with rc=%d\n", rc);
    }
    pIBRand->ourKemSecretKey.pData = (char *)pDecryptedData;
    pIBRand->ourKemSecretKey.cbData = cbDecryptedData;

    // Persist new KEM secretKey to file
    rc = WriteToFile(pIBRand->cfg.ourKemSecretKeyFilename, &(pIBRand->ourKemSecretKey), true);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to save KEM secret key to file \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename);
        return rc;
    }

    //dumpToFile("/home/jgilmore/dev/dump_KemSecretKey_D_raw.txt", (unsigned char *)pIBRand->ourKemSecretKey.pData, pIBRand->ourKemSecretKey.cbData);
    app_tracef("INFO: KEM key stored successfully (%lu bytes)", pIBRand->ourKemSecretKey.cbData);

    // Job done
    return 0;
}

//-----------------------------------------------------------------------
// DecapsulateAndStoreSharedSecret
//-----------------------------------------------------------------------
static int DecapsulateAndStoreSharedSecret(tIB_INSTANCEDATA *pIBRand)
{
    // If there is already a SharedSecret stored, then clear and free it.
    if (pIBRand->symmetricSharedSecret.pData)
    {
        memset(pIBRand->symmetricSharedSecret.pData, 0, pIBRand->symmetricSharedSecret.cbData);
        free(pIBRand->symmetricSharedSecret.pData);
        pIBRand->symmetricSharedSecret.pData = NULL;
        pIBRand->symmetricSharedSecret.cbData = 0;
    }

    // Check that we have the KEM secret key needed for the KEM decapsulation
    if (!pIBRand->ourKemSecretKey.pData || pIBRand->ourKemSecretKey.cbData == 0)
    {
        // This should never happen!
        app_tracef("ERROR: KEM secret key error (size=%d)", pIBRand->ourKemSecretKey.cbData);
        return 2201;
    }
    if (pIBRand->ourKemSecretKey.cbData != CRYPTO_SECRETKEYBYTES)
    {
        app_tracef("WARNING: Size of KEM secret key (%d) is not as expected (%d)", pIBRand->ourKemSecretKey.cbData, CRYPTO_SECRETKEYBYTES);
        //return 2202;
    }

    // Check that we have the encapsulated key
    if (!pIBRand->encapsulatedSharedSecret.pData || pIBRand->encapsulatedSharedSecret.cbData == 0)
    {
        app_tracef("ERROR: Encapsulated SharedSecret not found");
        return 2203;
    }

    unsigned char *p = (unsigned char *)pIBRand->encapsulatedSharedSecret.pData;
    size_t n = pIBRand->encapsulatedSharedSecret.cbData;
    //dumpToFile("/home/jgilmore/dev/dump_SharedSecret_A_quoted_base64_encapsulated_key.txt", p, n);

    //app_trace_hexall("DEBUG: base64 encoded encapsulatedSharedSecret:", pIBRand->encapsulatedSharedSecret.pData, pIBRand->encapsulatedSharedSecret.cbData);
    if (p[0] == '"') {p++; n--;}
    if (p[n-1] == '"') {n--;}
    //app_trace_hexall("DEBUG: p:", p, n);
    //dumpToFile("/home/jgilmore/dev/dump_SharedSecret_B_base64_encapsulated_key.txt", p, n);

    // base64_decode the encapsulate key
    size_t decodeSize = 0;
    unsigned char *rawEncapsulatedKey = base64_decode((char *)p, n, (size_t *)&(decodeSize));
    if (!rawEncapsulatedKey)
    {
       app_tracef("WARNING: Failed to decode Base64 EncapsulatedKey");
       return 2204;
    }
    //dumpToFile("/home/jgilmore/dev/dump_SharedSecret_C_encapsulated_key.txt", rawEncapsulatedKey, decodeSize);

    if (decodeSize != CRYPTO_CIPHERTEXTBYTES)
    {
        app_tracef("ERROR: Size of decoded encapsulated key (%u) is not as expected (%u)", decodeSize, CRYPTO_CIPHERTEXTBYTES);
        //app_trace_hexall("DEBUG: encapsulatedSharedSecret:", (char *)rawEncapsulatedKey, decodeSize);
        return 2205;
    }

    // Allocate a new buffer
    pIBRand->symmetricSharedSecret.pData = (char *)malloc(CRYPTO_BYTES);
    if (pIBRand->symmetricSharedSecret.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for new SharedSecret");
        return 2206;
    }
    // Initialise with something recognisable, so that we can ensure that it has worked
    memset(pIBRand->symmetricSharedSecret.pData, 0xAA, CRYPTO_BYTES);

    // Do the KEM decapsulation
    crypto_kem_dec((unsigned char *)pIBRand->symmetricSharedSecret.pData,
                   (unsigned char *)rawEncapsulatedKey,
                   (unsigned char *)pIBRand->ourKemSecretKey.pData);

    // We will set the size once we know it has completed
    pIBRand->symmetricSharedSecret.cbData = CRYPTO_BYTES;

    //dumpToFile("/home/jgilmore/dev/dump_SharedSecret_D_raw.txt", (unsigned char *)pIBRand->symmetricSharedSecret.pData, pIBRand->symmetricSharedSecret.cbData);
    app_tracef("INFO: SharedSecret stored successfully (%lu bytes)", pIBRand->symmetricSharedSecret.cbData);

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

    if (strlen(pIBRand->cfg.szAuthUrl) == 0)
    {
        app_tracef("ERROR: authenticateUser: Parameter error - AuthUrl is empty");
        return 2211;
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: authenticateUser: (\"%s\", \"%s\", \"%s\")", pIBRand->cfg.szAuthUrl, pIBRand->cfg.szUsername, pIBRand->cfg.szPassword);
    }
    else
    {
        app_tracef("INFO: Authenticating User: (\"%s\", \"%s\")", pIBRand->cfg.szAuthUrl, pIBRand->cfg.szUsername);
    }

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pIBRand->cfg.szAuthUrl);
//#define USE_CORRECT_ENGINE
#ifdef USE_CORRECT_ENGINE
    // Anything except ourselves.
    // Ideally: RAND_set_rand_engine(NULL)
    //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, "dynamic");
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: Force use of alternate OpenSSL RNG engine");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, "rdrand");
    //curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, NULL);
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
        app_tracef("INFO: CURLOPT_SSLENGINE_DEFAULT");
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE_DEFAULT, 1L);
#endif // USE_CORRECT_ENGINE

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
    //    app_tracef("INFO: Construct HTTP Headers");
    /* Pass our list of custom made headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Authorization: Bearer" );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);

    char bodyData[1024] = "";
    if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
    {
        sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", pIBRand->cfg.szUsername, pIBRand->cfg.szPassword );
    }
    else if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
        // We don't need nor rely on username and password when using a client certificate,
        // so we'll send just dummy credentials ("a" and "a")
        sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", "a", "a" );
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_POSTFIELDS, bodyData);

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_login);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);

    if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
#if 0
    INFO: Details of new client: {"clientCertName":"jgtestsrv1.com","clientCertSerialNumber":"42619BCC1CD78D32F18F0E40BC232452FCBBCA90","countryCode":"GB","smsNumber":"+447711221555","email":"me@home.com","keyparts":"2","kemAlgorithm":"222"}
    INFO: Sending NewClient request to https://jgtestsrv1.com/api/setupclient
    INFO: Client Setup Successful
    {
      "clientCertName":"jgtestsrv1.com",
      "clientCertSerialNumber":"42619BCC1CD78D32F18F0E40BC232452FCBBCA90",
      "countryCode":"GB",
      "smsNumber":"+447711221555",
      "email":"me@home.com",
      "keyparts":"2",
      "kemAlgorithm":"222"
    }
    ironbridge_clientsetup_OOB.json
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
        app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->cfg.szAuthSSLCertFile, pIBRand->cfg.szAuthSSLCertType);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->cfg.szAuthSSLCertFile);
            //return 55581;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->cfg.szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->cfg.szAuthSSLCertType); // Load the certificate type

        // SSL Key
        app_tracef("INFO: Using Client SSL key \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLKeyFile))
        {
            app_tracef("WARNING: Client SSL key file not found: \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
            //return 55582;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY     , pIBRand->cfg.szAuthSSLKeyFile ); // Load the key

    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: Connecting to \"%s\" with \"%s\"", pIBRand->cfg.szAuthUrl, bodyData);
    }

    /* Do it */
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: Sending \"%s\"", pIBRand->cfg.szAuthUrl );
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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: authenticateUser() Token = [%s]"            , pIBRand->Token.pData);
    }

    curl_slist_free_all(headers); /* free custom header list */
    app_tracef("INFO: Authentication successful: (\"%s\", \"%s\")", pIBRand->cfg.szAuthUrl, pIBRand->cfg.szUsername);
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

    if (pIBRand->cfg.useSecureRng)
    {
        szEndpoint = "srng";
    }
    else
    {
        szEndpoint = "rng";
    }

    pUrl = (char *)malloc(strlen(pIBRand->cfg.szBaseUrl)+strlen(szEndpoint)+2+MAXUINT_DIGITS); // i.e. strlen("/rng/NNNNNNN")
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 22230;
    }
    sprintf(pUrl,"%s/%s/%u", pIBRand->cfg.szBaseUrl, szEndpoint, pIBRand->cfg.bytesPerRequest);

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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: %s AuthHeader = \"%s\"", szEndpoint, pAuthHeader);
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
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s Sending \"%s\"", szEndpoint, pUrl );
    }
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: %s response code = %ld", szEndpoint, httpResponseCode);
    }
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: %s perform failed: [%s]", szEndpoint, curl_easy_strerror(curlResultCode));
        return 2232;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", szEndpoint, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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
// getSecureRNGSharedSecret
//-----------------------------------------------------------------------
int getNewKemKeyPair(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char *szEndpoint = "reqkeypair";

    pUrl = (char *)malloc(strlen(pIBRand->cfg.szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->cfg.szBaseUrl, szEndpoint);

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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: reqkeypair AuthHeader = \"%s\"", pAuthHeader);
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
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: reqkeypair Sending \"%s\"", pUrl );
    }
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: reqkeypair %ld", httpResponseCode);
    }
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: reqkeypair perform failed: [%s]", curl_easy_strerror(curlResultCode));
        curl_slist_free_all(headers); /* free custom header list */
        free(pAuthHeader);
        free(pUrl);
        return 2242;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: reqkeypair ResultantData = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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
// getSecureRNGSharedSecret
//-----------------------------------------------------------------------
int getSecureRNGSharedSecret(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    char *szEndpoint = "sharedsecret";

    pUrl = (char *)malloc(strlen(pIBRand->cfg.szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->cfg.szBaseUrl, szEndpoint);

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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: sharedsecret AuthHeader = \"%s\"", pAuthHeader);
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
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_SharedSecret);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);


    // Do it
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: sharedsecret Sending \"%s\"", pUrl );
    }
    curlResultCode = curl_easy_perform(pIBRand->hCurl);
    long httpResponseCode = 0;
    curl_easy_getinfo (pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: sharedsecret response code = %ld", httpResponseCode);
    }
    if (curlResultCode != CURLE_OK)
    {
        app_tracef("ERROR: sharedsecret perform failed: [%s]", curl_easy_strerror(curlResultCode));
        curl_slist_free_all(headers); /* free custom header list */
        free(pAuthHeader);
        free(pUrl);
        return 2242;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: sharedsecret ResultantData = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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
// prepareRNGBytes
//-----------------------------------------------------------------------
static bool prepareRNGBytes(tIB_INSTANCEDATA *pIBRand)
{
    // The data is currently Base64 encoded raw data

    // Format the output data
    if (strcmp(pIBRand->cfg.szStorageDataFormat,"RAW")==0)
    {
        // Curl_base64_decode() - Given a base64 string at src, decode it and return
        // an allocated memory in the *outptr. Returns the length of the decoded data.
        //*pcbData = Curl_base64_decode(p, (unsigned char **)ppData)
        // *ppData will, and must, be freed by the caller

        //dumpToFile("/home/jgilmore/dev/dump_Data_A_base64_encrypted_data.txt", p, n);

        //app_tracef("INFO: sharedsecret ResultantData[%u] = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
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
            return false;
        }
        free(pOriginalData);
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: %s ResultantData[%u]", pIBRand->cfg.useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData);
            //app_tracef("INFO: %s ResultantData[%u] = [%*.*s]", pIBRand->useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
        }
    }
    else if (strcmp(pIBRand->cfg.szStorageDataFormat,"BASE64")==0)
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
                return false;
            }
            memcpy(pIBRand->ResultantData.pData, pOriginalData+1, pIBRand->ResultantData.cbData);
            free(pOriginalData);
        }
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: %s ResultantData = [%*.*s]", pIBRand->cfg.useSecureRng?"SRNG":"RNG", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
        }
    }
    else if (strcmp(pIBRand->cfg.szStorageDataFormat,"HEX")==0)
    {
        // TODO
        app_tracef("WARNING: Storage data format \"%s\"  not yet implemented. Discarding %u bytes.", pIBRand->cfg.szStorageDataFormat, pIBRand->ResultantData.cbData);
        return false;
    }
    else
    {
        app_tracef("WARNING: Unsupported storage data format \"%s\". Discarding %u bytes.", pIBRand->cfg.szStorageDataFormat, pIBRand->ResultantData.cbData);
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------
// prepareSRNGBytes
//-----------------------------------------------------------------------
static bool prepareSRNGBytes(tIB_INSTANCEDATA *pIBRand)
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
        char *pReason = (my_errno == EINVAL) ? "Length not mod4" : (my_errno == ENOMEM) ? "Out of memory" : "Unspecified";
        app_tracef("WARNING: Failed to decode Base64 data (%s). Discarding %u bytes.", pReason, pIBRand->ResultantData.cbData);
        return false;
    }
    free(pIBRand->ResultantData.pData);
    pIBRand->ResultantData.pData = NULL;
    pIBRand->ResultantData.cbData = 0;

    //dumpToFile("/home/jgilmore/dev/dump_SRNG_C_encrypted_data.txt", pEncryptedData, cbEncryptedData);
    ///////////////////////////////////
    // Decrypt the data...
    ///////////////////////////////////

    if (pIBRand->symmetricSharedSecret.pData==NULL)
    {
        app_tracef("WARNING: Shared Secret not found");
#if 0
        // Now that we are running in a state machine, this should not be needed - BEGIN
        if (pIBRand->encapsulatedSharedSecret.pData==NULL)
        {
            // No keys found
            app_tracef("ERROR: No SharedSecret available to decryption SRNG response");
            return false; // todo cleanup
        }
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Decapsulating SharedSecret");
        int rc = DecapsulateAndStoreSharedSecret(pIBRand);
        if (rc != 0)
        {
            app_tracef("ERROR: KEM decapsulation failed with rc=%d", rc);
            return false; // todo cleanup
        }
        // Now that we are running in a state machine, this should not be needed - END
#endif
        // But still need to capture it's absence, Justin Case.
    }

#define USE_PBKDF2
#ifdef USE_PBKDF2
    unsigned char *pDecryptedData = NULL;
    size_t         cbDecryptedData = 0;
    int rc;

    rc = AESDecryptBytes(pEncryptedData, cbEncryptedData, (uint8_t *)pIBRand->symmetricSharedSecret.pData, pIBRand->symmetricSharedSecret.cbData, 32, &pDecryptedData, &cbDecryptedData);
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

    AES_set_decrypt_key((unsigned char *)pIBRand->symmetricSharedSecret.pData, pIBRand->symmetricSharedSecret.cbData*8, &dec_key); // Size of key is in bits
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        app_tracef("INFO: Decrypting %u bytes", pIBRand->symmetricSharedSecret.cbData);
    unsigned char *pRawData = (unsigned char *)malloc(cbEncryptedData);
    if (!pRawData)
    {
        app_tracef("ERROR: Malloc for decrypted data failed");
        return false; // todo cleanup
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
    if (strcmp(pIBRand->cfg.szStorageDataFormat,"RAW")!=0)
    {
        app_tracef("WARNING: Only RAW format is supported for SRNG. Discarding %u bytes.", pIBRand->ResultantData.cbData);
        return false; // todo cleanup
    }
    return true;
}

//-----------------------------------------------------------------------
// storeRandomBytes
//-----------------------------------------------------------------------
bool storeRandomBytes(tIB_INSTANCEDATA *pIBRand)
{
    int success;

    if (pIBRand->ResultantData.pData == NULL || pIBRand->ResultantData.cbData == 0)
    {
        // Nothing to do
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
        {
            app_tracef("INFO: Nothing to do. [pData=%p, cbData=%u]", pIBRand->ResultantData.pData, pIBRand->ResultantData.cbData);
        }
        return true;
    }

    if (pIBRand->cfg.useSecureRng)
    {
        success = prepareSRNGBytes(pIBRand);
        if (!success)
        {
            app_tracef("ERROR: Failed to prepare SRNG bytes");
            return false;
        }
    }
    else // RNG (pIBRand->useSecureRng == FALSE)
    {
        success = prepareRNGBytes(pIBRand);
        if (!success)
        {
            app_tracef("ERROR: Failed to prepare RNG bytes");
            return false;
        }
    } // RNG

    success = dataStore_Append(pIBRand);
    if (!success)
    {
        app_tracef("WARNING: Failed to append data to dataStore");
        return false;
    }
    return true;
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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
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
// DoSimpleAuthentication
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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: pRealToken = [%s]", pIBRand->pRealToken);
    }

    //fprintf(stderr, "DEBUG: Token.pData=[%s]\n", pIBRand->Token.pData);
    //fprintf(stderr, "DEBUG: pRealToken=[%s]\n", pIBRand->pRealToken);

    pIBRand->fAuthenticated = TRUE;
    return 0;
}

//-----------------------------------------------------------------------
// DoAuthentication
//-----------------------------------------------------------------------
int DoAuthentication(tIB_INSTANCEDATA *pIBRand)
{
    int rc;

    if (strcmp(pIBRand->cfg.szAuthType, "NONE") == 0)
    {
        // Nothing to do
        rc = 0;
    }
    if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
    {
        rc = DoSimpleAuthentication(pIBRand);
        if (rc != 0)
        {
            app_tracef("ERROR: Simple authentication failed rc=%d", rc);
            return rc;
        }
    }
    else if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
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
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
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
    if (pIBRand->symmetricSharedSecret.pData)
    {
        memset(pIBRand->symmetricSharedSecret.pData, 0, pIBRand->symmetricSharedSecret.cbData);
        free(pIBRand->symmetricSharedSecret.pData);
        pIBRand->symmetricSharedSecret.cbData = 0;
        pIBRand->symmetricSharedSecret.pData = NULL;
    }
    if (pIBRand->ourKemSecretKey.pData)
    {
        memset(pIBRand->ourKemSecretKey.pData, 0, pIBRand->ourKemSecretKey.cbData);
        free(pIBRand->ourKemSecretKey.pData);
        pIBRand->ourKemSecretKey.cbData = 0;
        pIBRand->ourKemSecretKey.pData = NULL;
    }
    // if (pIBRand->theirSigningPublicKey.pData)
    // {
    //     memset(pIBRand->theirSigningPublicKey.pData, 0, pIBRand->theirSigningPublicKey.cbData);
    //     free(pIBRand->theirSigningPublicKey.pData);
    //     pIBRand->theirSigningPublicKey.cbData = 0;
    //     pIBRand->theirSigningPublicKey.pData = NULL;
    // }
    curl_easy_cleanup(pIBRand->hCurl);
    curl_global_cleanup();

    if (pIBRand)
    {
        // Destory contents and free
        memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));
        free(pIBRand);
    }
}

static int ImportKemSecretKeyFromClientSetupOOBFile(tIB_INSTANCEDATA *pIBRand)
{
    int rc;
    tLSTRING binaryData = {0U, NULL};

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
        app_tracef("INFO: Importing KEM secret key from OOB file: \"%s\"", pIBRand->cfg.clientSetupOOBFilename);

    rc = GetBinaryDataFromOOBFile(pIBRand->cfg.clientSetupOOBFilename, &binaryData);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to get binary data from OOB file \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename);
        return rc;
    }

    rc = WriteToFile(pIBRand->cfg.ourKemSecretKeyFilename, &binaryData, true);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to write KEM secret key to file \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename);
        free(binaryData.pData);
        binaryData.pData = NULL;
        binaryData.cbData = 0;
        return rc;
    }

    free(binaryData.pData);
    binaryData.pData = NULL;
    binaryData.cbData = 0;
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
int ReadOurKemPrivateKey(tIB_INSTANCEDATA *pIBRand, size_t secretKeyBytes)
{
    int rc;

    if (my_fileExists(pIBRand->cfg.ourKemSecretKeyFilename))
    {
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
            app_tracef("INFO: KEM secret key exists at \"%s\". Client already initialised.", pIBRand->cfg.ourKemSecretKeyFilename );
    }
    else
    {
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
            app_tracef("INFO: KEM secret key not found at \"%s\". Client probably not initialised.", pIBRand->cfg.ourKemSecretKeyFilename );

        app_tracef("INFO: Initialising client from OOB data.", pIBRand->cfg.ourKemSecretKeyFilename );
        // Import secret key from clientsetup OOB file
        rc = ImportKemSecretKeyFromClientSetupOOBFile(pIBRand);
        if (rc != 0)
        {
            app_tracef("ERROR: Failed to import KEM secret key from OOB file");
            return rc;
        }
        // Import successful - fall through to ReadContentsOfFile
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
        app_tracef("INFO: Reading our KEM secret key from \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename );

    rc = ReadContentsOfFile(pIBRand->cfg.ourKemSecretKeyFilename, &pIBRand->ourKemSecretKey, secretKeyBytes);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to read KEM secret key from file \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename );
        return rc;
    }

    return 0;
}


// int ReadTheirSigningPublicKey(tIB_INSTANCEDATA *pIBRand, size_t publicKeyBytes)
// {
//     int rc;
//     if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
//         app_tracef("INFO: Reading their Signing public key from \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename );
//     rc = ReadContentsOfFile(pIBRand->cfg.theirSigningPublicKeyFilename, &pIBRand->theirSigningPublicKey, publicKeyBytes);
//     if (rc != 0)
//     {
//         app_tracef("ERROR: Failed to read their signing public key from \"%s\"", pIBRand->cfg.ourKemSecretKeyFilename );
//         return rc;
//     }
//     return 0;
// }

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

    app_tracef("===ibrand_service==================================================================================================");

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: ReadConfig");
    rc = ReadConfig(pIBRand->szConfigFilename, &(pIBRand->cfg), CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES);
    if (rc != 0)
    {
        fprintf(stderr, "FATAL: Configuration error. rc=%d\n", rc);
        app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

#ifdef FORCE_ALL_LOGGING_ON
    SET_BIT(pIBRand->cfg.fVerbose, DBGBIT_STATUS );
    SET_BIT(pIBRand->cfg.fVerbose, DBGBIT_CONFIG );
    SET_BIT(pIBRand->cfg.fVerbose, DBGBIT_AUTH   );
    SET_BIT(pIBRand->cfg.fVerbose, DBGBIT_DATA   );
    SET_BIT(pIBRand->cfg.fVerbose, DBGBIT_CURL   );
#endif // FORCE_ALL_LOGGING_ON


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
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
            app_tracef("INFO: IBRand Service started successfully (pid:%u)", processId);
        app_trace_closelog();
        exit(EXIT_SUCCESS);
    }

    /////////////////////////////////////////
    // We are the child process
    /////////////////////////////////////////
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: Daemon started");

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

#ifndef FORCE_ALL_LOGGING_ON
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

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CONFIG))
    {
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: PrintConfig");
        PrintConfig(&(pIBRand->cfg));
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: Service running");
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
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

    app_tracef("DEBUG: Calling dataStore_Initialise");
    if (!dataStore_Initialise(pIBRand))
    {
        // Log the failure
        app_tracef("FATAL: Failed to initialise datastore. Aborting");
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

    tSERVICESTATE currentState = STATE_START;
    bool continueInMainLoop = true;
    bool printProgressToSyslog = true;
    // The Big Loop
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: Enter State machine");
    while (continueInMainLoop)
    {
        if (printProgressToSyslog)
        {
            if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
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
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_START");

                pIBRand->ourKemSecretKey.pData        = NULL;
                pIBRand->ourKemSecretKey.cbData       = 0;
                rc = ReadOurKemPrivateKey(pIBRand, CRYPTO_SECRETKEYBYTES);
                if (rc != 0)
                {
                    fprintf(stderr, "FATAL: Configuration error. rc=%d\n", rc);
                    app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
                    app_trace_closelog();
                    free(pIBRand);
                    exit(EXIT_FAILURE);
                }

                // pIBRand->theirSigningPublicKey.pData  = NULL;
                // pIBRand->theirSigningPublicKey.cbData = 0;
                // rc = ReadTheirSigningPublicKey(pIBRand, CRYPTO_PUBLICKEYBYTES);
                // if (rc != 0)
                // {
                //     fprintf(stderr, "FATAL: Configuration error. rc=%d\n", rc);
                //     app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
                //     app_trace_closelog();
                //     free(pIBRand);
                //     exit(EXIT_FAILURE);
                // }

                currentState = STATE_INITIALISECURL;
                continue;

            case STATE_INITIALISECURL:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_INITIALISECURL");
                if (pIBRand->fCurlInitialised)
                {
                    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
                        app_tracef("INFO: Already initialised");
                    currentState = STATE_AUTHENTICATE;
                    continue;
                }
                rc = InitialiseCurl(pIBRand);
                if (rc != 0)
                {
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: InitialiseCurl failed with rc=%d. Will retry initialisation in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_INITIALISECURL;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: InitialiseCurl failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
                    app_tracef("INFO: Curl Initialisation OK");
                currentState = STATE_AUTHENTICATE;
                break;

            case STATE_AUTHENTICATE:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_AUTHENTICATE");
                printProgressToSyslog = true;
                if (pIBRand->fAuthenticated)
                {
                    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
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
                    app_tracef("ERROR: DoAuthentication failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_AUTHENTICATE;
    #else // RUN_AS_DAEMON
                    app_tracef("ERROR: DoAuthentication failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
    #endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Authentication OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_GETNEWSHAREDSECRET;
                break;

            case STATE_GETNEWKEMKEYPAIR:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_GETNEWKEMKEYPAIR");
                printProgressToSyslog = true;
                // Request a new KEM secret key
                rc = getNewKemKeyPair(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: getNewKemKeyPair failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
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
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_DECRYPTKEMSECRETKEY");
                // Do we have an encryptedKemSecretKey ?
                if (pIBRand->encryptedKemSecretKey.pData == NULL)
                {
                    currentState = STATE_GETNEWKEMKEYPAIR;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Decrypting KEM secret key");
                int rc = DecryptAndStoreKemSecretKey(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: Decryption of KEM secret key failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_DECAPSULATESHAREDSECRET;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: Decryption of KEM secret key failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: KEM Secret key OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_GETNEWSHAREDSECRET;
                break;

            case STATE_GETNEWSHAREDSECRET:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_GETNEWSHAREDSECRET");
                printProgressToSyslog = true;
                // Get SharedSecret
                rc = getSecureRNGSharedSecret(pIBRand);
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
                    app_tracef("ERROR: DoRequestSharedSecret failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_GETNEWSHAREDSECRET;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: DoRequestSharedSecret failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Encapsulated SharedSecret OK");
                currentState = STATE_DECAPSULATESHAREDSECRET;
                break;

            case STATE_DECAPSULATESHAREDSECRET:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_DECAPSULATESHAREDSECRET");
                // Do we have an encapsulatedSharedSecret ?
                if (pIBRand->encapsulatedSharedSecret.pData == NULL)
                {
                    currentState = STATE_GETNEWSHAREDSECRET;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Decapsulating SharedSecret");
                rc = DecapsulateAndStoreSharedSecret(pIBRand);
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
#ifdef RUN_AS_DAEMON
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_DECAPSULATESHAREDSECRET;
#else // RUN_AS_DAEMON
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Aborting.", rc);
                    currentState = STATE_SHUTDOWN;
#endif // RUN_AS_DAEMON
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: SharedSecret OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;

            case STATE_CHECKIFRANDOMNESSISREQUIRED:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_CHECKIFRANDOMNESSISREQUIRED");
                // Hysteresis
                pIBRand->datastoreFilesize = dataStore_GetCurrentWaterLevel(pIBRand);
                //app_tracef("DEBUG: Filesize=%d", pIBRand->datastoreFilesize);
                if (pIBRand->datastoreFilesize < 0) // File not found
                {
                    app_tracef("INFO: dataStore not found. Starting retrieval.", pIBRand->cfg.retrievalRetryDelay);
                    currentState = STATE_GETSOMERANDOMNESS;
                    continue;
                }
                if (pIBRand->isPaused) // We are waiting for the tank to drain
                {
                    if (pIBRand->datastoreFilesize <= pIBRand->cfg.storageLowWaterMark) // Is it nearly empty
                    {
                        app_tracef("INFO: Low water mark reached. Starting retrieval.", pIBRand->cfg.retrievalRetryDelay);
                        pIBRand->isPaused = false;
                        currentState = STATE_GETSOMERANDOMNESS;
                        continue;
                    }
                    // Fall through to sleep
                }
                else // We are busy filling up the tank
                {
                    // Does the tank still have space?
                    if (pIBRand->datastoreFilesize < pIBRand->cfg.storageHighWaterMark)
                    {
                        // Yes... got some more randomness
                        currentState = STATE_GETSOMERANDOMNESS;
                        continue;
                    }
                    // No. The tank is full.
                    app_tracef("INFO: High water mark reached. Pausing retrieval.", pIBRand->cfg.retrievalRetryDelay);
                    pIBRand->isPaused = true;
                    // Fall through to sleep
                }
                // Wait for a short while, and then try again
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
                    app_tracef("INFO: Idle. Sleeping for %d seconds", pIBRand->cfg.idleDelay);
                sleep(pIBRand->cfg.idleDelay);
                printProgressToSyslog = true;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;

            case STATE_GETSOMERANDOMNESS:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_GETSOMERANDOMNESS");
                printProgressToSyslog = true;
                // Get SharedSecret
                if (pIBRand->symmetricSharedSecret.pData == NULL)
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
                    app_tracef("ERROR: %s Failed with rc=%d. Will try again in %d seconds", pIBRand->cfg.useSecureRng?"SRNG":"RNG", rc, pIBRand->cfg.retrievalRetryDelay);
                    sleep(pIBRand->cfg.retrievalRetryDelay);
                    currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                    continue;
                }
                else if (pIBRand->ResultantData.pData == NULL || pIBRand->ResultantData.cbData == 0 )
                {
                    numberOfRetreivalFailures++;
                    numberOfConsecutiveRetreivalFailures++;
                    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
                        app_tracef("WARNING: %s No data received. Will try again in %d seconds", pIBRand->cfg.useSecureRng?"SRNG":"RNG", pIBRand->cfg.retrievalRetryDelay);
                    sleep(pIBRand->cfg.retrievalRetryDelay);
                    currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                    continue;
                }
                currentState = STATE_STORERANDOMNESS;
                break;

            case STATE_STORERANDOMNESS:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_STORERANDOMNESS");
                printProgressToSyslog = true;
                numberOfRetreivalSuccesses++;
                numberOfConsecutiveRetreivalFailures = 0;
                // pIBRand->ResultantData.pData must be freed by the caller
                bool success = storeRandomBytes(pIBRand);
                // Should be freed already, but just in case...
                if (pIBRand->ResultantData.pData)
                {
                    free(pIBRand->ResultantData.pData);
                    pIBRand->ResultantData.pData = NULL;
                }
                pIBRand->ResultantData.cbData = 0;

                // If there was a problem accessing the datastore, let's pause
                // and reflect for a few seconds instead of burning up the network.
                if (!success)
                {
                    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
                        app_tracef("INFO: Problem with datastore. Sleeping for %d seconds", pIBRand->cfg.idleDelay);
                    sleep(pIBRand->cfg.idleDelay);
                }

                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;

            case STATE_DESTROYEXISTINGSHAREDSECRET:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_DESTROYEXISTINGSHAREDSECRET");
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
                    app_tracef("INFO: Destroy SharedSecret, forcing renewal");

                // Destroy any existing encapsulatedSharedSecret, forcing the new one to be retrieved on next iteration on the main loop.
                if (pIBRand->encapsulatedSharedSecret.pData)
                {
                    memset(pIBRand->encapsulatedSharedSecret.pData, 0, pIBRand->encapsulatedSharedSecret.cbData);
                    free(pIBRand->encapsulatedSharedSecret.pData);
                    pIBRand->encapsulatedSharedSecret.pData = NULL;
                    pIBRand->encapsulatedSharedSecret.cbData = 0;
                }

                // Destroy any existing SharedSecret, forcing the new one to be decapsulated and used as and when needed.
                if (pIBRand->symmetricSharedSecret.pData)
                {
                    memset(pIBRand->symmetricSharedSecret.pData, 0, pIBRand->symmetricSharedSecret.cbData);
                    free(pIBRand->symmetricSharedSecret.pData);
                    pIBRand->symmetricSharedSecret.pData = NULL;
                    pIBRand->symmetricSharedSecret.cbData = 0;
                }
                currentState = STATE_GETNEWSHAREDSECRET;
                break;

            case STATE_SHUTDOWN:
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_SHUTDOWN");
                continueInMainLoop = false;
                break;
        }
    }

    ironbridge_api_finalise(pIBRand);

    app_tracef("WARNING: Terminating Service");
    app_trace_closelog();
    exit(EXIT_SUCCESS);
}
