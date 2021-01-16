///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
// Original: JGilmore (2020/06/23 15:26:31)
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
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

#include "../ibrand_common/my_utilslib.h"

#include "ibrand_service.h"
#include "ibrand_service_utils.h"
#include "ibrand_service_config.h"
#include "ibrand_service_kem.h"

typedef struct tagALGORITHM_NAME_ID
{
    const char *OQS_AlgorithmName;
    const int   CQC_AlgorithmID;
} tALGORITHM_NAME_ID;

static tALGORITHM_NAME_ID kemAlgorithmNameAndId[] =
{
    {"BIKE1-L13-CPA"              , 111},    // BIKE1-L13-CPA KEM
    {"BIKE1-L3-CPA"               , 112},    // BIKE1-L3-CPA KEM
    {"BIKE1-L1-FO"                , 113},    // BIKE1-L1-FO KEM
    {"BIKE1-L3-FO"                , 114},    // BIKE1-L3-FO KEM
    {"Classic-McEliece-348864"    , 322},    // Classic-McEliece-348864 KEM
    {"Classic-McEliece-348864f"   , 323},    // Classic-McEliece-348864f KEM
    {"Classic-McEliece-460896"    , 324},    // Classic-McEliece-460896 KEM
    {"Classic-McEliece-460896f"   , 325},    // Classic-McEliece-460896f KEM
    {"Classic-McEliece-6688128"   , 326},    // Classic-McEliece-6688128 KEM
    {"Classic-McEliece-6688128f"  , 327},    // Classic-McEliece-6688128f KEM
    {"Classic-McEliece-6960119"   , 328},    // Classic-McEliece-6960119 KEM
    {"Classic-McEliece-6960119f"  , 329},    // Classic-McEliece-6960119f KEM
    {"Classic-McEliece-8192128"   , 330},    // Classic-McEliece-8192128 KEM
    {"Classic-McEliece-8192128f"  , 331},    // Classic-McEliece-8192128f KEM
    {"HQC-128-1-CCA2"             , 350},    // HQC-128-1-CCA2 KEM
    {"HQC-192-1-CCA2"             , 351},    // HQC-192-1-CCA2 KEM
    {"HQC-192-2-CCA2"             , 352},    // HQC-192-2-CCA2 KEM
    {"HQC-256-1-CCA2"             , 353},    // HQC-256-1-CCA2 KEM
    {"HQC-256-2-CCA2"             , 354},    // HQC-256-2-CCA2 KEM
    {"HQC-256-3-CCA2"             , 355},    // HQC-256-3-CCA2 KEM
    {"Kyber512"                   , 380},    // Kyber512 KEM
    {"Kyber768"                   , 381},    // Kyber768 KEM
    {"Kyber1024"                  , 382},    // Kyber1024 KEM
    {"Kyber512-90s"               , 383},    // Kyber512-90s KEM
    {"Kyber768-90s"               , 384},    // Kyber768-90s KEM
    {"Kyber1024-90s"              , 385},    // Kyber1024-90s KEM
    {"NTRU-HPS-2048-509"          , 390},    // NTRU-HPS-2048-509 KEM
    {"NTRU-HPS-2048-677"          , 391},    // NTRU-HPS-2048-677 KEM
    {"NTRU-HPS-4096-821"          , 392},    // NTRU-HPS-4096-821 KEM
    {"NTRU-HRSS-701"              , 393},    // NTRU-HRSS-701 KEM
    {"LightSaber-KEM"             , 400},    // LightSaber-KEM KEM
    {"Saber-KEM"                  , 401},    // Saber-KEM KEM
    {"FireSaber-KEM"              , 402},    // FireSaber-KEM KEM
    {"FrodoKEM-640-AES"           , 222},    // FrodoKEM-640-AES KEM
    {"FrodoKEM-640-SHAKE"         , 223},    // FrodoKEM-640-SHAKE KEM
    {"FrodoKEM-976-AES"           , 224},    // FrodoKEM-976-AES KEM
    {"FrodoKEM-976-SHAKE"         , 225},    // FrodoKEM-976-SHAKE KEM
    {"FrodoKEM-1344-AES"          , 226},    // FrodoKEM-1344-AES KEM
    {"FrodoKEM-1344-SHAKE"        , 227},    // FrodoKEM-1344-SHAKE KEM
    {"SIDH-p434"                  , 250},    // SIDH p434 KEM
    {"SIDH-p434-compressed"       , 251},    // SIDH p434 compressed KEM
    {"SIDH-p503"                  , 252},    // SIDH p503 KEM
    {"SIDH-p503-compressed"       , 253},    // SIDH p503 compressed KEM
    {"SIDH-p610"                  , 254},    // SIDH p610 KEM
    {"SIDH-p610-compressed"       , 255},    // SIDH p610 compressed KEM
    {"SIDH-p751"                  , 256},    // SIDH p751 KEM
    {"SIDH-p751-compressed"       , 257},    // SIDH p751 compressed KEM
    {"SIKE-p434"                  , 258},    // SIKE p434 KEM
    {"SIKE-p434-compressed"       , 259},    // SIKE p434 compressed KEM
    {"SIKE-p503"                  , 260},    // SIKE p503 KEM
    {"SIKE-p503-compressed"       , 261},    // SIKE p503 compressed KEM
    {"SIKE-p610"                  , 262},    // SIKE p610 KEM
    {"SIKE-p610-compressed"       , 263},    // SIKE p610 compressed KEM
    {"SIKE-p751"                  , 264},    // SIKE p751 KEM
    {"SIKE-p751-compressed"       , 265},    // SIKE p751 compressed KEM
    {""                           , 999}     // EOF Marker
};

const char *KemLookupOqsAlgorithmName(int CqcAlgorithmId)
{
    for (int ii=0; ;ii++)
    {
        if (kemAlgorithmNameAndId[ii].CQC_AlgorithmID == 999)
            break;
        if (kemAlgorithmNameAndId[ii].CQC_AlgorithmID == CqcAlgorithmId)
        {
            return kemAlgorithmNameAndId[ii].OQS_AlgorithmName;
        }
    }
    return NULL;
}

bool KemAlgorithmIsValid(const char *algorithmName, bool *pIsSupported, bool *pIsEnabled)
{
    *pIsSupported = false;
    *pIsEnabled = false;

    int numAlgorithms = OQS_KEM_alg_count();
    for (int ii = 0; ii < numAlgorithms; ii++)
    {
        const char *algo = OQS_KEM_alg_identifier(ii);
        //app_tracef("    DEBUG: Supported algo: %s (enabled=%d)", algo, OQS_KEM_alg_is_enabled(algo));
        if (my_stricmp(algo, algorithmName) == 0)
        {
            *pIsSupported = true;
            // Determine if the algorithm is enabled
            if (OQS_KEM_alg_is_enabled(algorithmName) == 1)
            {
                *pIsEnabled = true;
            }
            break;
        }
    }
    // return true if supported and enabled
    return *pIsSupported && *pIsEnabled;
}

tERRORCODE KemDecapsulateSharedSecret(int cqcKemAlgorithmId,
                               tLSTRING *pSharedSecret,
                               const tLSTRING *pEncapsulatedSharedSecret,
                               const tLSTRING *pKemSecretKey)
{
    const char *szKemAlgorithm = KemLookupOqsAlgorithmName(cqcKemAlgorithmId);
    if (!szKemAlgorithm)
    {
        app_tracef("ERROR: Unknown KEM algorithm ID: %d", cqcKemAlgorithmId);
        return ERC_IBKEM_PARAMERR_UNKNOWN_ALGO_ID;
    }
    bool isSupported = false;
    bool isEnabled = false;
    if (!KemAlgorithmIsValid(szKemAlgorithm, &isSupported, &isEnabled))
    {
        app_tracef("ERROR: Mechanism not supported and/or not enabled: %s (supported=%d, enabled=%d)", szKemAlgorithm, isSupported, isEnabled);
        return ERC_IBKEM_PARAMERR_ALGO_NOT_SUPPORTED_OR_NOT_ENABLED;
    }

    OQS_KEM *pOQSInstance;
    pOQSInstance = OQS_KEM_new(szKemAlgorithm);
    if (pOQSInstance == NULL)
    {
        app_tracef("ERROR: Failed to instantiate KEM Algorithm: %s", szKemAlgorithm);
        return ERC_IBKEM_ALGO_INSTANTIATE_FAILED;
    }
    // pSharedSecret->pData points to a pre-allocated buffer of CRYPTO_MAXSHAREDSECRETBYTES
    // and pSharedSecret->cbData is currently set to the size of that malloc.
    if (pSharedSecret->cbData < pOQSInstance->length_shared_secret)
    {
        app_tracef("ERROR: SharedSecret buffer (%u) too small for maximum length of decapsulated shared secret (%u)", pSharedSecret->cbData, pOQSInstance->length_shared_secret);
        OQS_KEM_free(pOQSInstance);
        return ERC_IBKEM_SHSEC_BUFFER_TOO_SMALL;
    }
    pSharedSecret->cbData = pOQSInstance->length_shared_secret; // We are losing the original size of the malloc, but it shouldn't matter at all.

    // Avoid: ERROR: Size of EncapsulatedSharedSecret (9720) is not as expected (16)
    //if (pEncapsulatedSharedSecret->cbData != pOQSInstance->length_shared_secret)
    //{
    //    app_tracef("ERROR: Size of EncapsulatedSharedSecret (%u) is not as expected (%u)", pEncapsulatedSharedSecret->cbData, pOQSInstance->length_shared_secret);
    //    OQS_KEM_free(pOQSInstance);
    //    return ERC_IBKEM_SHSEC_SIZE_ERROR;
    //}
    if (pKemSecretKey->cbData != pOQSInstance->length_secret_key)
    {
        app_tracef("ERROR: Size of KemSecretKey (%u) is not as expected (%u)", pKemSecretKey->cbData, pOQSInstance->length_secret_key);
        OQS_KEM_free(pOQSInstance);
        return ERC_IBKEM_KEMKEY_SIZE_ERROR;
    }

    // Do the KEM decapsulation
    OQS_STATUS oqsStatus;
    oqsStatus = OQS_KEM_decaps(pOQSInstance,
                             (uint8_t *)pEncapsulatedSharedSecret->pData,
                             (uint8_t *)pSharedSecret->pData,
                             (uint8_t *)pKemSecretKey->pData);
    if (oqsStatus != OQS_SUCCESS) // e.g. OQS_ERROR or OQS_EXTERNAL_LIB_ERROR_OPENSSL
    {
        app_tracef("ERROR: OQS KEM failed with oqsStatus=%u", oqsStatus);
        OQS_KEM_free(pOQSInstance);
        return ERC_IBKEM_KEM_DECAP_FAILED;
    }

    OQS_KEM_free(pOQSInstance);
    return ERC_OK;
}
