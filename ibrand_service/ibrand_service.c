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

#include "ibrand_service_kem.h"

#include "../ibrand_common/my_utilslib.h"

#include "ibrand_service.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_config.h"
#include "ibrand_service_datastore.h"

#include "../ibrand_common/my_utilslib.h"
#include "ibrand_service_aes.h"


#if LIBCURL_VERSION_NUM < 0x070c03
#error "ERROR - Requires libcurl of 7.12.3 or greater"
#endif

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
#define HTTP_RESP_KEMKEYPAIREXPIRED      (499) // TokenExpiredOrInvalid 498
#define HTTP_RESP_SHAREDSECRETEXPIRED    (498) // TokenExpiredOrInvalid 498


//#define KAT_KNOWN_ANSWER_TESTING

/////////////////////////////////////
// Forward declarations
/////////////////////////////////////
static int DecryptAndStoreKemSecretKey(tIB_INSTANCEDATA *pIBRand);
static int DecapsulateAndStoreSharedSecret(tIB_INSTANCEDATA *pIBRand);
static int ImportKemSecretKeyFromClientSetupOOBFile(tIB_INSTANCEDATA *pIBRand);

#ifdef KAT_KNOWN_ANSWER_TESTING
///////////////////////////////////////////////////////
// KAT - Known Answer Test
// For info: A 16 byte shared secret of "CambridgeQuantum" translates to "Q2FtYnJpZGdlUXVhbnR1bQ==" in Base64.
///////////////////////////////////////////////////////
static void KatDataAppend(tLSTRING *pDest, int destOffset, int numBytesToAppend)
{
    //const char *pSrc = "The Quick Brown Fox Jumped Over The Lazy Dog. ";
    const char *pSrc = "CambridgeQuantumComputingLimited"; // Convenient 32 bytes
    //const char *pSrc = "UpcomingMildAutumnTimeBirdcageQt"; // Anagram of the above
    size_t cbSrc = strlen(pSrc);

    while (numBytesToAppend > 0)
    {
        int bytesToCopy = my_minimum(cbSrc, numBytesToAppend);
        memcpy(pDest->pData + destOffset, pSrc, bytesToCopy);
        pDest->cbData += bytesToCopy;
        numBytesToAppend -= bytesToCopy;
    }
}

static bool KatDataVerify(tLSTRING *pActualData, size_t expectedLength, char *szTitle)
{
    tLSTRING expectedData;
    expectedData.pData = (char *)malloc(expectedLength);
    expectedData.cbData = 0;
    KatDataAppend(&expectedData, 0, expectedLength);
    if (pActualData->cbData != expectedLength)
    {
        app_tracef("WARNING: PassthroughTesting failed. %s length mismatch: actual:%u vs expected:%u", szTitle, pActualData->cbData, expectedLength);
        return false;
    }
    if (memcmp(pActualData->pData, expectedData.pData, expectedLength) != 0)
    {
        app_tracef("WARNING: PassthroughTesting failed. %s content mismatch", szTitle);
        return false;
    }
    return true;
}
#endif // KAT_KNOWN_ANSWER_TESTING

void DestroyAndFreeExistingItem(tLSTRING *pItem)
{
    if (pItem->pData)
    {
        memset(pItem->pData, 0, pItem->cbData);
        free(pItem->pData);
        pItem->pData = NULL;
        pItem->cbData = 0;
    }
}

static bool copyToNewBuffer (tLSTRING *pDest, tLSTRING *pSrc, bool appendToExistingData)
{
    // Alloc (or Realloc) a new buffer for the data, and free previous buffer, if there was one
    tLSTRING freeMe;
    tLSTRING existingData;
    tLSTRING result;

    // Save the details of the original buffer so that we can destroy and free it at the end.
    freeMe = *pDest;
    existingData = *pDest;

    if (!appendToExistingData)
    {
        existingData.cbData = 0;
    }
    result.cbData = existingData.cbData + pSrc->cbData;

    // Alloc/Realloc a new buffer
    result.pData = (char *)malloc(result.cbData);
    if (result.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound KEM data");
        return false;
    }
    if (appendToExistingData && existingData.pData && existingData.cbData)
    {
        memcpy(result.pData, existingData.pData, existingData.cbData);
    }
    // Concatenate the data
    memcpy(result.pData + existingData.cbData, pSrc->pData, pSrc->cbData);

    // Free up the old buffer, if there is one
    DestroyAndFreeExistingItem(&freeMe);

    // We will set the size once we know it has completed
    pDest->pData = result.pData;
    pDest->cbData = result.cbData;

    return true;
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_login
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->authToken)
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_login(char *buffer, size_t size, size_t nmemb, void *userp)
{
    tLSTRING inboundData;
    tIB_INSTANCEDATA *pIBRand;

    inboundData.pData = buffer;
    inboundData.cbData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() UserData is NULL");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: Login: %u bytes received", inboundData.cbData);
        app_trace_hex("DEBUG: ReceiveDataHandler_login:", (unsigned char *)inboundData.pData, inboundData.cbData);
    }

    // Free up the old buffer, if there is one
    DestroyAndFreeExistingItem(&pIBRand->authToken);

    // Allocate a new buffer
    pIBRand->authToken.pData = (char *)malloc(inboundData.cbData);
    if (pIBRand->authToken.pData == NULL)
    {
        app_tracef("ERROR: ReceiveDataHandler_login() malloc failure");
        return 0; // Zero bytes processed
    }

    // Copy in the new data
    memcpy(pIBRand->authToken.pData, inboundData.pData, inboundData.cbData);
    pIBRand->authToken.cbData = inboundData.cbData;

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: ReceiveDataHandler_login() Saved %lu bytes", pIBRand->authToken.cbData);
    }

    // Job done
    return inboundData.cbData;  // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_rng
// This is our CURLOPT_WRITEFUNCTION
// and userp is our CURLOPT_WRITEDATA (&pIBRand->authToken)
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_rng(char *buffer, size_t size, size_t nmemb, void *userp)
{
    tLSTRING inboundData;
    tIB_INSTANCEDATA *pIBRand;

    inboundData.pData = buffer;
    inboundData.cbData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_rng() UserData is NULL");
        return 0; // Zero bytes processed
    }

    pIBRand->encryptedRng_RcvdSegments++;

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: rng request: %u bytes received (segment %d)",
                   inboundData.cbData,
                   pIBRand->encryptedRng_RcvdSegments);
        app_trace_hex("DEBUG: ReceiveDataHandler_rng: ", (unsigned char *)inboundData.pData, inboundData.cbData);
    }

    size_t prevLen = pIBRand->ResultantData.cbData;

    // Alloc (or Realloc) a new buffer for the data, and free previous buffer, if there was one
    bool rc = copyToNewBuffer (&(pIBRand->ResultantData),
                               &inboundData,
                               //(pIBRand->encryptedKemSecretKey_RcvdSegments > 1) ); // If this is the 2nd or subsequent segment, then append
                               (pIBRand->ResultantData.cbData > 0) ); // If the buffer already holds some data, then append
    if (!rc)
    {
        app_tracef("ERROR: ReceiveDataHandler_rng() malloc failure");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: Segment %d of encryptedRng received successfully (%lu + %lu = %lu bytes)",
                   pIBRand->encryptedRng_RcvdSegments,
                   prevLen,
                   inboundData.cbData,
                   pIBRand->ResultantData.cbData);
    }

    // Job done
    return inboundData.cbData; // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_RequestNewKeyPair
// This is our CURLOPT_WRITEFUNCTION
// and userp is our encryptedKemSecretKey
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_RequestNewKeyPair(char *buffer, size_t size, size_t nmemb, void *userp)
{
    tLSTRING inboundData;
    tIB_INSTANCEDATA *pIBRand;

    inboundData.pData = buffer;
    inboundData.cbData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_RequestNewKeyPair() UserData is NULL");
        return 0; // Zero bytes processed
    }

    pIBRand->encryptedKemSecretKey_RcvdSegments++;

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: RequestNewKeyPair: %u bytes received (segment %d)",
                   inboundData.cbData,
                   pIBRand->encryptedKemSecretKey_RcvdSegments);
        app_trace_hex("DEBUG: ReceiveDataHandler_RequestNewKeyPair:", (unsigned char *)inboundData.pData, inboundData.cbData);
    }

    size_t prevLen = pIBRand->encryptedKemSecretKey.cbData;

    // Alloc (or Realloc) a new buffer for the data, and free previous buffer, if there was one
    bool rc = copyToNewBuffer (&(pIBRand->encryptedKemSecretKey),
                               &inboundData,
                               (pIBRand->encryptedKemSecretKey_RcvdSegments > 1) ); // If this is the 2nd or subsequent segment, then append
    if (!rc)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound encrypted data");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: Segment %d of encryptedKemSecretKey received successfully (%lu + %lu = %lu bytes)",
                   pIBRand->encryptedKemSecretKey_RcvdSegments,
                   prevLen,
                   inboundData.cbData,
                   pIBRand->encryptedKemSecretKey.cbData);
    }

    // Destroy any existing KEM secret key, forcing the new one to be decrypted and used as and when needed.
    DestroyAndFreeExistingItem(&pIBRand->ourKemSecretKey);

    // Job done
    return inboundData.cbData; // Number of bytes processed
}

//-----------------------------------------------------------------------
// ReceiveDataHandler_SharedSecret
// This is our CURLOPT_WRITEFUNCTION
// and userp is our encapsulatedSharedSecret
//-----------------------------------------------------------------------
size_t ReceiveDataHandler_SharedSecret(char *buffer, size_t size, size_t nmemb, void *userp)
{
    tLSTRING inboundData;
    tIB_INSTANCEDATA *pIBRand;

    inboundData.pData = buffer;
    inboundData.cbData = (size * nmemb);

    // Cast our userp back to its original (tIB_INSTANCEDATA *) type
    pIBRand = (tIB_INSTANCEDATA *)userp;
    if (!pIBRand)
    {
        app_tracef("ERROR: ReceiveDataHandler_SharedSecret() UserData is NULL");
        return 0; // Zero bytes processed
    }

    pIBRand->encapsulatedSharedSecret_RcvdSegments++;

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: SharedSecret: %u bytes received (segment %d)",
                   inboundData.cbData,
                   pIBRand->encapsulatedSharedSecret_RcvdSegments);
        app_trace_hex("DEBUG: ReceiveDataHandler_SharedSecret:", (unsigned char *)inboundData.pData, inboundData.cbData);
    }

    size_t prevLen = pIBRand->encapsulatedSharedSecret.cbData;

    // Alloc (or Realloc) a new buffer for the data, and free previous buffer, if there was one
    bool rc = copyToNewBuffer (&(pIBRand->encapsulatedSharedSecret),
                               &inboundData,
                               (pIBRand->encapsulatedSharedSecret_RcvdSegments > 1) ); // If this is the 2nd or subsequent segment, then append
    if (!rc)
    {
        app_tracef("ERROR: Failed to allocate storage for inbound KEM data");
        return 0; // Zero bytes processed
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    {
        app_tracef("INFO: Segment %d of encapsulatedSharedSecret received successfully (%lu + %lu = %lu bytes)",
                   pIBRand->encapsulatedSharedSecret_RcvdSegments,
                   prevLen,
                   inboundData.cbData,
                   pIBRand->encapsulatedSharedSecret.cbData);
    }

    // Destroy any existing SharedSecret, forcing the new one to be decapsulated and used as and when needed.
    DestroyAndFreeExistingItem(&pIBRand->symmetricSharedSecret);

    // Job done
    return inboundData.cbData; // Number of bytes processed
}

#define SHAREDSECRET_CRYPTO_BYTES (123)  // (CRYPTO_BYTES) TODO

//-----------------------------------------------------------------------
// DecryptAndStoreKemSecretKey
//-----------------------------------------------------------------------
static int DecryptAndStoreKemSecretKey(tIB_INSTANCEDATA *pIBRand)
{
    int errcode;

    // If there is already a KEM secret key stored, then clear and free it.
    DestroyAndFreeExistingItem(&pIBRand->ourKemSecretKey);

    errcode = AESDecryptPackage(pIBRand,
                                &pIBRand->encryptedKemSecretKey, // Source
                                &pIBRand->ourKemSecretKey,       // Destination
                                0,                               // expectedSize not specified (CRYPTO_CIPHERTEXTBYTES) (TODO)
                                true);                           // hasHeader
    if (errcode)
    {
        app_tracef("ERROR: Error %d - Failed to decrypt payload", errcode);
        return errcode;
    }

    // Persist new KEM secretKey to file
    errcode = WriteToFile(pIBRand->cfg.ourKemSecretKeyFilename, &pIBRand->ourKemSecretKey, true);
    if (errcode != 0)
    {
        app_tracef("ERROR: Error %d - Failed to save KEM secret key to file \"%s\"", errcode, pIBRand->cfg.ourKemSecretKeyFilename);
        return errcode;
    }

#ifdef KAT_KNOWN_ANSWER_TESTING
    size_t expectedLength = 9616; // Size of Frodo KEM private key
    // TODO: Extend to support alogorithms other than just Frodo
    KatDataVerify(&(pIBRand->ourKemSecretKey), expectedLength, "KemSecretKey");
#endif // KAT_KNOWN_ANSWER_TESTING

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
    DestroyAndFreeExistingItem(&pIBRand->symmetricSharedSecret);

    // Check that we have the KEM secret key needed for the KEM decapsulation
    if (!pIBRand->ourKemSecretKey.pData || pIBRand->ourKemSecretKey.cbData == 0)
    {
        // This should never happen!
        app_tracef("ERROR: KEM secret key error (size=%d)", pIBRand->ourKemSecretKey.cbData);
        return 2201;
    }
    // Check that we have the encapsulated key
    if (!pIBRand->encapsulatedSharedSecret.pData || pIBRand->encapsulatedSharedSecret.cbData == 0)
    {
        app_tracef("ERROR: Encapsulated SharedSecret not found");
        return 2203;
    }

    unsigned char *p = (unsigned char *)pIBRand->encapsulatedSharedSecret.pData;
    size_t n = pIBRand->encapsulatedSharedSecret.cbData;

    //app_trace_hexall("DEBUG: base64 encoded encapsulatedSharedSecret:", (unsigned char *)pIBRand->encapsulatedSharedSecret.pData, pIBRand->encapsulatedSharedSecret.cbData);

    if (p[0] == '"') {p++; n--;}
    if (p[n-1] == '"') {n--;}
    //app_trace_hexall("DEBUG: p:", p, n);

    // base64_decode the encapsulate key
    tLSTRING rawEncapsulatedSharedSecret;
    rawEncapsulatedSharedSecret.cbData = 0;
    rawEncapsulatedSharedSecret.pData = (char *)base64_decode((char *)p, n, &rawEncapsulatedSharedSecret.cbData);
    if (!rawEncapsulatedSharedSecret.pData)
    {
       app_tracef("WARNING: Failed to decode Base64 encapsulatedSharedSecret");
       if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
       {
           app_trace_hexall("DEBUG: Base64 encapsulatedSharedSecret: ", p, n);
       }
       return 2204;
    }

    // Allocate a new buffer
    pIBRand->symmetricSharedSecret.pData = (char *)malloc(SHAREDSECRET_CRYPTO_BYTES);
    if (pIBRand->symmetricSharedSecret.pData == NULL)
    {
        app_tracef("ERROR: Failed to allocate storage for new SharedSecret");
        return 2206;
    }
    // Initialise with something recognisable, so that we can ensure that it has worked
    memset(pIBRand->symmetricSharedSecret.pData, 0xAA, SHAREDSECRET_CRYPTO_BYTES);

    // Do the KEM decapsulation
    int rc = KemDecapsulateSharedSecret("FrodoKEM-640",
                                        &pIBRand->symmetricSharedSecret,
                                        &rawEncapsulatedSharedSecret,
                                        &pIBRand->ourKemSecretKey);
    if (rc != 0)
    {
        app_tracef("ERROR: Failed to decapsulate new SharedSecret");
        return 2207;
    }
    // We will set the size once we know it has completed
    pIBRand->symmetricSharedSecret.cbData = SHAREDSECRET_CRYPTO_BYTES;

#ifdef KAT_KNOWN_ANSWER_TESTING
    size_t expectedLength = SHAREDSECRET_CRYPTO_BYTES; // Size of the SharedSecret
    KatDataVerify(&(pIBRand->symmetricSharedSecret), expectedLength, "SharedSecret");
#endif // KAT_KNOWN_ANSWER_TESTING

    app_tracef("INFO: SharedSecret stored successfully (%lu bytes)", pIBRand->symmetricSharedSecret.cbData);

    // Job done
    return 0;
}


static bool SetPreferredRngEngine(tIB_INSTANCEDATA *pIBRand)
{
    // Force use of non-IronBridge OpenSSL RNG engine
    // Anything except ourselves (ibrand).
    CURLcode ret;
    const char *szPreferredRngEngine = NULL; // options: NULL, "rdrand", "dynamic", "md_rand"

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: Set preferred OpenSSL RNG engine: %s", szPreferredRngEngine?szPreferredRngEngine:"NULL");
    }

    // https://wiki.openssl.org/index.php/Random_Numbers#Generators says...
    // By default, OpenSSL uses the md_rand generator. md_rand uses the MD5 hash as the pseudorandom function.
    // The source code is located in crypto/rand/md_rand.c.

    ret = curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE, szPreferredRngEngine);
    if (ret != CURLE_OK)
    {
        // e.g. CURLE_SSL_ENGINE_INITFAILED (66) : Initiating the SSL Engine failed.
        //      CURLE_SSL_ENGINE_NOTFOUND   (53) : The specified crypto engine wasn't found.
        app_tracef("ERROR: CURLOPT_SSLENGINE (%s) failed with ret=%d", szPreferredRngEngine?szPreferredRngEngine:"NULL",ret);
        return false;
    }
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
    {
        app_tracef("INFO: CURLOPT_SSLENGINE_DEFAULT");
    }
    ret = curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLENGINE_DEFAULT, 1L);
    if (ret != CURLE_OK)
    {
        // e.g. CURLE_SSL_ENGINE_SETFAILED  (54) : Failed setting the selected SSL crypto engine as default!
        app_tracef("ERROR: CURLOPT_SSLENGINE_DEFAULT (%s) failed with ret=%d", szPreferredRngEngine?szPreferredRngEngine:"NULL",ret);
        return false;
    }
    return true;
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
        app_tracef("INFO: Authenticating User: (\"%s\", \"%s\")", pIBRand->cfg.szAuthUrl, pIBRand->cfg.szUsername);
        //app_tracef("INFO: authenticateUser: (\"%s\", \"%s\", \"%s\")", pIBRand->cfg.szAuthUrl, pIBRand->cfg.szUsername, pIBRand->cfg.szPassword);
    }

    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pIBRand->cfg.szAuthUrl);
    if (!SetPreferredRngEngine(pIBRand))
    {
        app_tracef("ERROR: Failed to set preferred openssl RNG engine for SSL connection");
        return 2212;
    }

    // Pass our list of custom made headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Authorization: Bearer" );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);

    char bodyData[1024] = "";
    sprintf(bodyData, "{\"Username\":\"%s\",\"Password\":\"%s\"}", pIBRand->cfg.szUsername, pIBRand->cfg.szPassword );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_POSTFIELDS, bodyData);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_login);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
        // Client Certificate
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->cfg.szAuthSSLCertFile, pIBRand->cfg.szAuthSSLCertType);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->cfg.szAuthSSLCertFile);
            //return 55581;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->cfg.szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->cfg.szAuthSSLCertType); // Load the certificate type

        // SSL Key
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
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

    // Do it
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

    long resultCode = 0;
    CURLcode curlResultCodeB;
    curlResultCodeB = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_HTTP_CONNECTCODE, &resultCode);
    if (!curlResultCodeB && resultCode)
    {
        app_tracef("ERROR: authenticateUser: ResultCode=%03ld \"%s\"", resultCode, curl_easy_strerror(curlResultCodeB));
        return 2220;
    }

    long response_code = 0;
    CURLcode  curlResultCodeC;
    curlResultCodeC = curl_easy_getinfo(pIBRand->hCurl, CURLINFO_RESPONSE_CODE, &response_code);
    if (!curlResultCodeC && (response_code != 200))
    {
        app_tracef("ERROR: authenticateUser: HTTP Responcse Code=%ld", response_code);
        return 2221;
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
            app_tracef("INFO: authenticateUser() authToken = [%s]"            , pIBRand->authToken.pData);
    }

    curl_slist_free_all(headers); // Free custom header list
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
    const char * szEndpoint;
    char *pAuthHeader = NULL;
    #define MAXUINT_DIGITS 20 // 0x7FFF FFFF FFFF FFFF = 9,223,372,036,854,775,807 ==> 19 digits for signed, 20 for unsigned.

    szEndpoint = (pIBRand->cfg.useSecureRng) ? "srng":"rng";

    pUrl = (char *)malloc(strlen(pIBRand->cfg.szBaseUrl)+strlen(szEndpoint)+2+MAXUINT_DIGITS); // i.e. strlen("/rng/NNNNNNN")
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 22230;
    }
    sprintf(pUrl,"%s/%s/%u", pIBRand->cfg.szBaseUrl, szEndpoint, pIBRand->cfg.bytesPerRequest);
    if (!SetPreferredRngEngine(pIBRand))
    {
        app_tracef("ERROR: Failed to set preferred openssl RNG engine for SSL connection");
        return 22233;
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    // Pass our list of custom made headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
    {
        // e.g.
        //   "name": "accept",
        //   "value": "application/json, text/plain, */*"
        //   "name": "authorization",
        //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
        //   "name": "content-type",
        //   "value": "application/json"

        pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
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
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_rng);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    // Prepare the pIBRand for the new block of data
    pIBRand->encryptedRng_RcvdSegments = 0;

    if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
        // Client Certificate
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->cfg.szAuthSSLCertFile, pIBRand->cfg.szAuthSSLCertType);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->cfg.szAuthSSLCertFile);
            //return 55581;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->cfg.szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->cfg.szAuthSSLCertType); // Load the certificate type

        // SSL Key
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using Client SSL key \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLKeyFile))
        {
            app_tracef("WARNING: Client SSL key file not found: \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
            //return 55582;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY     , pIBRand->cfg.szAuthSSLKeyFile ); // Load the key
    }

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
        if (httpResponseCode == HTTP_RESP_SHAREDSECRETEXPIRED)
        {
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            free(pUrl);
            return ERC_OopsSharedSecretExpired;
        }
        if (httpResponseCode == HTTP_RESP_KEMKEYPAIREXPIRED)
        {
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            free(pUrl);
            return ERC_OopsKemKeyPairExpired;
        }
        app_tracef("ERROR: %s perform failed: curl:%ld [%s] http:%ld [%s]", szEndpoint, curlResultCode, curl_easy_strerror(curlResultCode), httpResponseCode, HttpResponseCodeDescription(httpResponseCode));
        if (pIBRand->ResultantData.pData && pIBRand->ResultantData.cbData)
        {
            app_tracef("ERROR: %s response: [%s]", szEndpoint, pIBRand->ResultantData);
        }
        curl_slist_free_all(headers); // Free custom header list
        if (pAuthHeader) free(pAuthHeader);
        free(pUrl);
        return 2232;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: %s ResultantData = [%*.*s]", szEndpoint, pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    curl_slist_free_all(headers); // Free custom header list
    if (pAuthHeader) free(pAuthHeader);
    free(pUrl);
    return 0;
}

//-----------------------------------------------------------------------
// getNewKemKeyPair
//-----------------------------------------------------------------------
int getNewKemKeyPair(tIB_INSTANCEDATA *pIBRand)
{
    CURLcode curlResultCode;
    char * pUrl;
    const char *szEndpoint = "reqkeypair";
    char *pAuthHeader = NULL;

    pUrl = (char *)malloc(strlen(pIBRand->cfg.szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->cfg.szBaseUrl, szEndpoint);
    if (!SetPreferredRngEngine(pIBRand))
    {
        app_tracef("ERROR: Failed to set preferred openssl RNG engine for SSL connection");
        return 22401;
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    // Pass our list of custom made headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
    {
        // e.g.
        //   "name": "accept",
        //   "value": "application/json, text/plain, */*"
        //   "name": "authorization",
        //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
        //   "name": "content-type",
        //   "value": "application/json"
        pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
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
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_RequestNewKeyPair);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    // Prepare the pIBRand for the new shared secret
    pIBRand->encryptedKemSecretKey_RcvdSegments = 0;

    if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
        // Client Certificate
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->cfg.szAuthSSLCertFile, pIBRand->cfg.szAuthSSLCertType);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->cfg.szAuthSSLCertFile);
            //return 55581;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->cfg.szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->cfg.szAuthSSLCertType); // Load the certificate type

        // SSL Key
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using Client SSL key \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLKeyFile))
        {
            app_tracef("WARNING: Client SSL key file not found: \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
            //return 55582;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY     , pIBRand->cfg.szAuthSSLKeyFile ); // Load the key
    }

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
        if (httpResponseCode == HTTP_RESP_SHAREDSECRETEXPIRED)
        {
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            free(pUrl);
            return ERC_OopsSharedSecretExpired;
        }
        if (httpResponseCode == HTTP_RESP_KEMKEYPAIREXPIRED)
        {
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            free(pUrl);
            return ERC_OopsKemKeyPairExpired;
        }

        app_tracef("ERROR: %s perform failed: curl:%ld [%s] http:%ld [%s]", "reqkeypair", curlResultCode, curl_easy_strerror(curlResultCode), httpResponseCode, HttpResponseCodeDescription(httpResponseCode));
        if (pIBRand->encryptedKemSecretKey.pData && pIBRand->encryptedKemSecretKey.cbData)
        {
            app_tracef("ERROR: %s response: [%s]", szEndpoint, pIBRand->encryptedKemSecretKey);
        }
        curl_slist_free_all(headers); // Free custom header list
        if (pAuthHeader) free(pAuthHeader);
        free(pUrl);
        return 2242;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: reqkeypair ResultantData = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    curl_slist_free_all(headers); // Free custom header list
    if (pAuthHeader) free(pAuthHeader);
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
    const char *szEndpoint = "sharedsecret";
    char *pAuthHeader = NULL;

    pUrl = (char *)malloc(strlen(pIBRand->cfg.szBaseUrl)+1+strlen(szEndpoint)+1);
    if (!pUrl)
    {
        app_tracef("ERROR: Out of memory allocating for URL");
        return 2240;
    }
    sprintf(pUrl,"%s/%s", pIBRand->cfg.szBaseUrl, szEndpoint);
    if (!SetPreferredRngEngine(pIBRand))
    {
        app_tracef("ERROR: Failed to set preferred openssl RNG engine for SSL connection");
        return 22402;
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPGET, TRUE );
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_URL, pUrl);

    // Pass our list of custom made headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append ( headers, "Content-Type: application/json" );
    headers = curl_slist_append ( headers, "Accept: application/json, text/plain, */*" );
    if (strcmp(pIBRand->cfg.szAuthType, "SIMPLE") == 0)
    {
        // e.g.
        //   "name": "accept",
        //   "value": "application/json, text/plain, */*"
        //   "name": "authorization",
        //   "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InVzZXIxIiwibmJmIjoxNTczODM5ODU0LCJleHAiOjE1NzM5MjYyNTQsImlhdCI6MTU3MzgzOTg1NCwiaXNzIjoiaHR0cHM6Ly9pcm9uYnJpZGdlYXBpLmNvbSIsImF1ZCI6IkFueSJ9.sTD67YPrCdj1RWOqa8R3Pc3j7DA88mF8x0oD2ZMbmQ0"
        //   "name": "content-type",
        //   "value": "application/json"
        pAuthHeader = (char *)malloc(strlen(pIBRand->pRealToken)+30u); // i.e. + strlen("Authorization: Bearer ")
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
    }
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEFUNCTION, ReceiveDataHandler_SharedSecret);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_WRITEDATA, pIBRand);
    curl_easy_setopt(pIBRand->hCurl, CURLOPT_FAILONERROR, true);

    // Prepare the pIBRand for the new shared secret
    pIBRand->encapsulatedSharedSecret_RcvdSegments = 0;

    if (strcmp(pIBRand->cfg.szAuthType, "CLIENT_CERT") == 0)
    {
        // Client Certificate
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using client certificate \"%s\" of type \"%s\"", pIBRand->cfg.szAuthSSLCertFile, pIBRand->cfg.szAuthSSLCertType);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLCertFile))
        {
            app_tracef("WARNING: Client Certificate file not found: \"%s\"", pIBRand->cfg.szAuthSSLCertFile);
            //return 55581;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERT    , pIBRand->cfg.szAuthSSLCertFile); // Load the certificate
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLCERTTYPE, pIBRand->cfg.szAuthSSLCertType); // Load the certificate type

        // SSL Key
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
            app_tracef("INFO: Using Client SSL key \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
        if (!my_fileExists(pIBRand->cfg.szAuthSSLKeyFile))
        {
            app_tracef("WARNING: Client SSL key file not found: \"%s\"", pIBRand->cfg.szAuthSSLKeyFile);
            //return 55582;
        }
        curl_easy_setopt(pIBRand->hCurl, CURLOPT_SSLKEY     , pIBRand->cfg.szAuthSSLKeyFile ); // Load the key
    }

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
        if (httpResponseCode == HTTP_RESP_SHAREDSECRETEXPIRED)
        {
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            free(pUrl);
            return ERC_OopsSharedSecretExpired;
        }
        if (httpResponseCode == HTTP_RESP_KEMKEYPAIREXPIRED)
        {
            curl_slist_free_all(headers); // Free custom header list
            if (pAuthHeader) free(pAuthHeader);
            free(pUrl);
            return ERC_OopsKemKeyPairExpired;
        }
        app_tracef("ERROR: %s perform failed: curl:%ld [%s] http:%ld [%s]", "sharedsecret", curlResultCode, curl_easy_strerror(curlResultCode), httpResponseCode, HttpResponseCodeDescription(httpResponseCode));
        if (pIBRand->encapsulatedSharedSecret.pData && pIBRand->encapsulatedSharedSecret.cbData)
        {
            app_tracef("ERROR: %s response: [%s]", szEndpoint, pIBRand->encapsulatedSharedSecret);
        }
        curl_slist_free_all(headers); // Free custom header list
        if (pAuthHeader) free(pAuthHeader);
        free(pUrl);
        return 2252;
    }

    //if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
    //{
    //    app_tracef("INFO: sharedsecret ResultantData = [%*.*s]", pIBRand->ResultantData.cbData, pIBRand->ResultantData.cbData, pIBRand->ResultantData.pData);
    //}

    curl_slist_free_all(headers); // Free custom header list
    if (pAuthHeader) free(pAuthHeader);
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
        // *pcbData = Curl_base64_decode(p, (unsigned char **)ppData)
        // *ppData will, and must, be freed by the caller

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
            pIBRand->ResultantData.pData = (char *)malloc(pIBRand->ResultantData.cbData);
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
    int errcode;
    tLSTRING decryptedData = {0, NULL};

    errcode = AESDecryptPackage(pIBRand,
                                &pIBRand->ResultantData,      // Source
                                &decryptedData,               // Destination
                                pIBRand->cfg.bytesPerRequest, // expectedSize
                                true);                        // hasHeader
    if (errcode)
    {
        app_tracef("ERROR: Error %d - Failed to decrypt payload", errcode);
        return false;
    }

    // Destroy and free inbound encrypted material
    DestroyAndFreeExistingItem(&pIBRand->ResultantData);

    // And take on the buffer containing the newly decrypted data
    pIBRand->ResultantData = decryptedData;

    // The data is now raw data
    if (strcmp(pIBRand->cfg.szStorageDataFormat,"RAW")!=0)
    {
        app_tracef("WARNING: Only RAW format is supported for SRNG. Discarding %u bytes.", pIBRand->ResultantData.cbData);
        return false;
    }

#ifdef KAT_KNOWN_ANSWER_TESTING
    size_t expectedLength = pIBRand->ResultantData.cbData; // TODO: Use the Size of the SRNG Request
    KatDataVerify(&(pIBRand->ResultantData), expectedLength, "SRNG");
#endif // KAT_KNOWN_ANSWER_TESTING

    return true;
}

//-----------------------------------------------------------------------
// storeRandomBytes
//-----------------------------------------------------------------------
static bool storeRandomBytes(tIB_INSTANCEDATA *pIBRand, tLSTRING *pResultantData)
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

    success = dataStore_Append(pIBRand, pResultantData);
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
    // In windows, this will init the winsock stuff
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
    pIBRand->authToken.pData = NULL;
    pIBRand->authToken.cbData = 0;
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
    pIBRand->pRealToken = ExtractSubstring(pIBRand->authToken.pData, "\"token\":\"", "\"");
    if (!pIBRand->pRealToken)
    {
        // Check with space after colon
        pIBRand->pRealToken = ExtractSubstring(pIBRand->authToken.pData, "\"token\": \"", "\"");
        if (!pIBRand->pRealToken)
        {
          app_tracef("ERROR: Cannot find token in TokenData pData=[%s]", pIBRand->authToken.pData);
          return 2270;
        }
    }

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
    {
        app_tracef("INFO: pRealToken = [%s]", pIBRand->pRealToken);
    }

    //app_tracef("[ibrand-service] DEBUG: authToken.pData=[%s]", pIBRand->authToken.pData);
    //app_tracef("[ibrand-service] DEBUG: pRealToken=[%s]", pIBRand->pRealToken);

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
        // Nothing special required here
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

    DestroyAndFreeExistingItem(&pIBRand->ResultantData);
    DestroyAndFreeExistingItem(&pIBRand->authToken);
    DestroyAndFreeExistingItem(&pIBRand->symmetricSharedSecret);
    DestroyAndFreeExistingItem(&pIBRand->ourKemSecretKey);
    //DestroyAndFreeExistingItem(&pIBRand->theirSigningPublicKey);

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
        DestroyAndFreeExistingItem(&binaryData);
        return rc;
    }

    DestroyAndFreeExistingItem(&binaryData);
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
    pid_t processId = {0};
    pid_t sessionId = {0};
    int rc;
    tIB_INSTANCEDATA *pIBRand;

    UNUSED_PARAM(argc);
    UNUSED_PARAM(argv);

    // =========================================================================
    // Create instance storage
    // =========================================================================
    pIBRand = (tIB_INSTANCEDATA *)malloc(sizeof(tIB_INSTANCEDATA));
    if (!pIBRand)
    {
        app_tracef("[ibrand-service] FATAL: Failed to allocate memory for local storage. Aborting.");
        return EXIT_FAILURE;
    }
    memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));

    // =========================================================================
    // And they're off!!!
    // =========================================================================
    fprintf(stdout, "IronBridge(tm) IBRand Service v0.40\n");
    fprintf(stdout, "Copyright (c) 2020 Cambridge Quantum Computing Limited. All rights reserved.\n");
    fprintf(stdout, "\n");

    if (argc > 1)
    {
        fprintf(stderr, "ERROR: Commandline parameter \"%s\" not supported\n", argv[1]);
        free(pIBRand);
        return EXIT_FAILURE;
    }

    char *tempPtr = NULL;
    rc = my_getFilenameFromEnvVar("IBRAND_CONF", &tempPtr);
    if ((rc != 0) || (tempPtr == NULL) || strlen(tempPtr)==0)
    {
        fprintf(stderr, "FATAL: Config environment variable \"IBRAND_CONF\" not found or invalid.\n");
        free(pIBRand);
        return EXIT_FAILURE;
    }

    my_strlcpy(pIBRand->szConfigFilename, tempPtr, sizeof(pIBRand->szConfigFilename));
    free(tempPtr);

    app_trace_set_destination(false, false, true); // (toConsole, toLogFile; toSyslog)
    app_trace_openlog(NULL, LOG_PID, LOG_DAEMON);

    app_tracef("===ibrand_service==================================================================================================");

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: ReadConfig \"%s\"", pIBRand->szConfigFilename);

    //rc = ReadConfig(pIBRand->szConfigFilename, &(pIBRand->cfg), CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES);
    rc = ReadConfig(pIBRand->szConfigFilename, &(pIBRand->cfg), 0, 0);
    if (rc != 0)
    {
        app_tracef("FATAL: Configuration error while processing \"%s\". Aborting. rc=%d", pIBRand->szConfigFilename, rc);
        app_trace_closelog();
        free(pIBRand);
        return EXIT_FAILURE;
    }

    // Fork off the parent process
    processId = fork();
    if (processId < 0)
    {
        app_tracef("FATAL: Failed to create child process. Aborting.");
        app_trace_closelog();
        free(pIBRand);
        return EXIT_FAILURE;
    }
    // If we got a good pid, then we can exit the parent process.
    if (processId > 0)
    {
        /////////////////////////////////////////
        // We are the parent process
        /////////////////////////////////////////
        fprintf(stdout, "[ibrand-service] INFO: IBRand Service started successfully (pid:%u)\n", processId);
        if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
            app_tracef("INFO: IBRand Service started successfully (pid:%u)", processId);
        app_trace_closelog();
        return EXIT_SUCCESS;
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
        return EXIT_FAILURE;
    }

    // Change the current working directory
    if ((chdir("/")) < 0)
    {
        // Log the failure
        app_tracef("FATAL: Chdir failed. Aborting");
        app_trace_closelog();
        free(pIBRand);
        return EXIT_FAILURE;
    }

    // Curl logging is sent to stdout
    // So if DBGBIT_CURL bit is set, then do not close stdout etc.
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
    {
        // Leave the standard file descriptors open
    }
    else
    {
        // Close out the standard file descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

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
    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS)) app_tracef("INFO: Running");

    unsigned long numberOfAuthSuccesses =  0;
    unsigned long numberOfAuthFailures =  0;
    unsigned long numberOfConsecutiveAuthFailures =  0;

    unsigned long numberOfRetreivalSuccesses =  0;
    unsigned long numberOfRetreivalFailures =  0;
    unsigned long numberOfConsecutiveRetreivalFailures =  0;

    pIBRand->ResultantData.pData = NULL;
    pIBRand->ResultantData.cbData = 0;

    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA)) app_tracef("DEBUG: Calling dataStore_Initialise");
    if (!dataStore_Initialise(pIBRand))
    {
        // Log the failure
        app_tracef("FATAL: Failed to initialise datastore. Aborting");
        app_trace_closelog();
        free(pIBRand);
        return EXIT_FAILURE;
    }

    tSERVICESTATE currentState = STATE_START;
    bool continueInMainLoop = true;
    bool printProgressToSyslog = true;
    bool printSleepMessageToSyslog = true;

    long currentWaterLevel = 0;
    bool isPaused = false;

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
                                "STORE(%s,L%ld))",
                                numberOfAuthSuccesses, numberOfAuthFailures, numberOfConsecutiveAuthFailures,
                                numberOfRetreivalSuccesses, numberOfRetreivalFailures, numberOfConsecutiveRetreivalFailures,
                                isPaused?"Draining":"Filling ", currentWaterLevel);
            }
            printProgressToSyslog = false;
        }
        switch (currentState)
        {
            case STATE_START:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_START");

                pIBRand->ourKemSecretKey.pData        = NULL;
                pIBRand->ourKemSecretKey.cbData       = 0;

                //rc = ReadOurKemPrivateKey(pIBRand, CRYPTO_SECRETKEYBYTES);
                rc = ReadOurKemPrivateKey(pIBRand, 0);
                if (rc != 0)
                {
                    app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
                    app_trace_closelog();
                    free(pIBRand);
                    return EXIT_FAILURE;
                }

                // pIBRand->theirSigningPublicKey.pData  = NULL;
                // pIBRand->theirSigningPublicKey.cbData = 0;
                // rc = ReadTheirSigningPublicKey(pIBRand, CRYPTO_PUBLICKEYBYTES);
                // if (rc != 0)
                // {
                //     app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
                //     app_trace_closelog();
                //     free(pIBRand);
                //     return EXIT_FAILURE;
                // }

                currentState = STATE_INITIALISECURL;
                continue;
            }
            case STATE_INITIALISECURL:
            {
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
                    app_tracef("ERROR: InitialiseCurl failed with rc=%d. Will retry initialisation in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_INITIALISECURL;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_CURL))
                    app_tracef("INFO: Curl Initialisation OK");
                currentState = STATE_AUTHENTICATE;
                break;
            }
            case STATE_AUTHENTICATE:
            {
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
                    app_tracef("ERROR: DoAuthentication failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_AUTHENTICATE;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Authentication OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_GETNEWSHAREDSECRET;
                break;
            }
            case STATE_GETNEWKEMKEYPAIR:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_GETNEWKEMKEYPAIR");
                printProgressToSyslog = true;
                // Request a new KEM secret key
                rc = getNewKemKeyPair(pIBRand);
                if (rc == ERC_OopsSharedSecretExpired)
                {
                    currentState = STATE_DESTROYEXISTINGSHAREDSECRET;
                    continue;
                }
                else if (rc == ERC_OopsKemKeyPairExpired)
                {
                    currentState = STATE_GETNEWKEMKEYPAIR;
                    continue;
                }
                if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
                    app_tracef("ERROR: getNewKemKeyPair failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_GETNEWKEMKEYPAIR;
                    continue;
                }
                currentState = STATE_DECRYPTKEMSECRETKEY;
                break;
            }
            case STATE_DECRYPTKEMSECRETKEY:
            {
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
                    app_tracef("ERROR: Decryption of KEM secret key failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_DECAPSULATESHAREDSECRET;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: KEM Secret key OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_GETNEWSHAREDSECRET;
                break;
            }
            case STATE_GETNEWSHAREDSECRET:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_GETNEWSHAREDSECRET");
                printProgressToSyslog = true;
                // Get SharedSecret
                rc = getSecureRNGSharedSecret(pIBRand);
                if (rc == ERC_OopsSharedSecretExpired)
                {
                    currentState = STATE_DESTROYEXISTINGSHAREDSECRET;
                    continue;
                }
                else if (rc == ERC_OopsKemKeyPairExpired)
                {
                    currentState = STATE_GETNEWKEMKEYPAIR;
                    continue;
                }
                else if (rc != 0)
                {
                    numberOfAuthFailures++;
                    numberOfConsecutiveAuthFailures++;
                    app_tracef("ERROR: DoRequestSharedSecret failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_GETNEWSHAREDSECRET;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: Encapsulated SharedSecret OK");
                currentState = STATE_DECAPSULATESHAREDSECRET;
                break;
            }
            case STATE_DECAPSULATESHAREDSECRET:
            {
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
                    app_tracef("ERROR: KEM decapsulation failed with rc=%d. Will retry in %d seconds", rc, pIBRand->cfg.authRetryDelay);
                    sleep(pIBRand->cfg.authRetryDelay);
                    currentState = STATE_DECAPSULATESHAREDSECRET;
                    continue;
                }
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_AUTH))
                    app_tracef("INFO: SharedSecret OK");
                numberOfAuthSuccesses++;
                numberOfConsecutiveAuthFailures = 0;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;
            }
            case STATE_CHECKIFRANDOMNESSISREQUIRED:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_CHECKIFRANDOMNESSISREQUIRED");
                // Hysteresis
                currentWaterLevel = dataStore_GetCurrentWaterLevel(pIBRand);
                if (currentWaterLevel < 0)
                {
                    app_tracef("INFO: Starting initial retrieval");
                    currentState = STATE_GETSOMERANDOMNESS;
                    continue;
                }
                if (isPaused) // We are waiting for the tank to drain
                {
                    if (currentWaterLevel <= dataStore_GetLowWaterMark(pIBRand)) // Is it nearly empty
                    {
                        app_tracef("INFO: LowWaterMark reached. Starting retrieval.");
                        isPaused = false;
                        currentState = STATE_GETSOMERANDOMNESS;
                        continue;
                    }
                    // Fall through to sleep
                }
                else // We are busy filling up the tank
                {
                    // Does the tank still have space?
                    if (currentWaterLevel < dataStore_GetHighWaterMark(pIBRand))
                    {
                        // Yes... got some more randomness
                        currentState = STATE_GETSOMERANDOMNESS;
                        continue;
                    }
                    // No. The tank is full.
                    app_tracef("INFO: HighWaterMark reached. Pausing retrieval.");
                    isPaused = true;
                    // Fall through to sleep
                }
                // Wait for a short while, and then try again
                if (printSleepMessageToSyslog)
                {
                    if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_STATUS))
                    {
                        app_tracef("INFO: Idle. Sleeping. Checking water level every %d seconds", pIBRand->cfg.idleDelay);
                    }
                    printSleepMessageToSyslog = false;
                }
                sleep(pIBRand->cfg.idleDelay);
                printProgressToSyslog = false;
                currentState = STATE_CHECKIFRANDOMNESSISREQUIRED;
                break;
            }
            case STATE_GETSOMERANDOMNESS:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_GETSOMERANDOMNESS");
                printProgressToSyslog = true;
                printSleepMessageToSyslog = true;
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
                else if (rc == ERC_OopsKemKeyPairExpired)
                {
                    currentState = STATE_GETNEWKEMKEYPAIR;
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
            }
            case STATE_STORERANDOMNESS:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_STORERANDOMNESS");
                printProgressToSyslog = false;
                numberOfRetreivalSuccesses++;
                numberOfConsecutiveRetreivalFailures = 0;
                // pIBRand->ResultantData.pData must be freed by the caller
                bool success = storeRandomBytes(pIBRand, &(pIBRand->ResultantData));
                // Should be freed already, but just in case...
                DestroyAndFreeExistingItem(&pIBRand->ResultantData);

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
            }
            case STATE_DESTROYEXISTINGSHAREDSECRET:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_DESTROYEXISTINGSHAREDSECRET");
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_DATA))
                    app_tracef("INFO: Destroy SharedSecret, forcing renewal");

                // Destroy any existing encapsulatedSharedSecret, forcing the new one to be retrieved on next iteration on the main loop.
                DestroyAndFreeExistingItem(&pIBRand->encapsulatedSharedSecret);
                // Destroy any existing SharedSecret, forcing the new one to be decapsulated and used as and when needed.
                DestroyAndFreeExistingItem(&pIBRand->symmetricSharedSecret);

                currentState = STATE_GETNEWSHAREDSECRET;
                break;
            }
            case STATE_SHUTDOWN:
            {
                if (TEST_BIT(pIBRand->cfg.fVerbose,DBGBIT_PROGRESS)) app_tracef("PROGRESS: STATE_SHUTDOWN");
                continueInMainLoop = false;
                break;
            }
        }
    }

    ironbridge_api_finalise(pIBRand);

    app_tracef("WARNING: Terminating Service");
    app_trace_closelog();
    return EXIT_SUCCESS;
}
