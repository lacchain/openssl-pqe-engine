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

bool KemAlgorithmIsValid(char *algorithmName, bool *pIsSupported, bool *pIsEnabled)
{
    *pIsSupported = false;
    *pIsEnabled = false;

    int numAlgorithms = OQS_KEM_alg_count();
    for (int ii = 0; ii < numAlgorithms; ii++)
    {
        const char *algo = OQS_KEM_alg_identifier(ii);
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

int KemDecapsulateSharedSecret(char *kemAlgorithm,
                               tLSTRING *pSharedSecret,
                               const tLSTRING *pEncapsulatedSharedSecret,
                               const tLSTRING *pKemSecretKey)
{
    // Do the KEM decapsulation
    OQS_KEM *pOQSInstance;
    bool isSupported = false;
    bool isEnabled = false;
    if (!KemAlgorithmIsValid(kemAlgorithm, &isSupported, &isEnabled))
    {
        // Mechanism not supported and/or not enabled
        return 9991;
    }
    pOQSInstance = OQS_KEM_new(kemAlgorithm);
    if (pOQSInstance == NULL)
    {
        // Failed to instantiate KEM
        return 9993;
    }
    if (pSharedSecret->cbData != pOQSInstance->length_shared_secret)
    {
        // SharedSecret buffer too small for decapsulated shared secret
        OQS_KEM_free(pOQSInstance);
        return 9993;
    }
    if (pEncapsulatedSharedSecret->cbData != pOQSInstance->length_shared_secret)
    {
        // Size of EncapsulatedSharedSecret is not as expected
        OQS_KEM_free(pOQSInstance);
        return 9993;
    }
    if (pKemSecretKey->cbData != pOQSInstance->length_secret_key)
    {
        // Size of KemSecretKey is not as expected
        OQS_KEM_free(pOQSInstance);
        return 9993;
    }
    OQS_STATUS oqsStatus;
    oqsStatus = OQS_KEM_decaps(pOQSInstance,
                             (uint8_t *)pEncapsulatedSharedSecret->pData,
                             (uint8_t *)pSharedSecret->pData,
                             (uint8_t *)pKemSecretKey->pData);
    if (oqsStatus != OQS_SUCCESS) // e.g. OQS_ERROR or OQS_EXTERNAL_LIB_ERROR_OPENSSL
    {
        // OQS KEM exception
        OQS_KEM_free(pOQSInstance);
        return 9993;
    }
    OQS_KEM_free(pOQSInstance);

    return 0;
}

#if 0
static OQS_STATUS example_heap(void)
{
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;

    // Create an OQS generic KEM object
    kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL)
    {
        printf("[example_heap]  OQS_KEM_frodokem_640_aes was not enabled at compile-time.\n");
        return OQS_ERROR;
    }

    // Malloc the required memory
    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    ciphertext = malloc(kem->length_ciphertext);
    shared_secret_e = malloc(kem->length_shared_secret);
    shared_secret_d = malloc(kem->length_shared_secret);

    if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL) || (shared_secret_d == NULL))
    {
        fprintf(stderr, "ERROR: malloc failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    // Create Key Pair
    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    if (rc != OQS_SUCCESS)
    {
        fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    // Encapsulate Shared Secret
    rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS)
    {
        fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    // Decapsulate Shared Secret
    rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS)
    {
        fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    // All Done
    printf("[example_heap]  OQS_KEM_frodokem_640_aes operations completed.\n");
    cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);

    return OQS_SUCCESS; // success
}
#endif
