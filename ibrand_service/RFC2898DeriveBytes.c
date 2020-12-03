
// RFC2898DeriveBytes.c
// Password-Based Key Derivation Function: PBKDF2
// This wrapper: JGilmore 20-Jul-2020

// References used...
//   https://stackoverflow.com/questions/55015935/equivalent-of-rfc2898derivebytes-in-c-without-using-clr
//   https://stackoverflow.com/questions/9771212/how-to-use-pkcs5-pbkdf2-hmac-sha1

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include <my_utilslib.h>
#include "RFC2898DeriveBytes.h"

//#define PKCS5_PBKDF2_HMAC_ITERATIONS 1000 // Reference code
//#define PKCS5_PBKDF2_HMAC_ITERATIONS 317771 // A nice big prime number - just for fun, but a large impact on performance
#define PKCS5_PBKDF2_HMAC_ITERATIONS 11113 // A smaller prime number - still just for fun.


tRfc2898DeriveBytes *Rfc2898DeriveBytes_Init( const uint8_t *pSecret, uint32_t cbSecret, const uint8_t *pSalt, uint32_t cbSalt )
{
    tRfc2898DeriveBytes *p;

    if (cbSecret > SECRET_MAXSIZE)
    {
        app_tracef("ERROR: Parameter error. Secret too big. (%lu > %lu)", cbSecret, SECRET_MAXSIZE);
        return NULL;
    }
    if (cbSalt > SALT_MAXSIZE)
    {
        app_tracef("ERROR: Parameter error. Salt too big. (%lu > %lu)", cbSalt, SALT_MAXSIZE);
        return NULL;
    }
    p = malloc(sizeof(tRfc2898DeriveBytes));
    if (!p)
    {
        app_tracef("ERROR: malloc of Rfc2898DeriveBytes failed");
        return NULL;
    }
    memcpy(p->pSecret, pSecret, cbSecret);
    p->cbSecret = cbSecret;
    if (pSalt == NULL)
    {
        uint8_t *pGeneratedSalt = malloc(cbSalt);
        if (!pGeneratedSalt)
        {
            app_tracef("ERROR: malloc of pGeneratedSalt failed");
            free(p);
            return NULL;
        }
        for (size_t ii=0; ii<cbSalt; ii++ )
        {
            pGeneratedSalt[ii] = (uint8_t)rand(); // TODO - use IB randomness
        }
        memcpy(p->pSalt, pGeneratedSalt, cbSalt);
        p->cbSalt = cbSalt;
        free(pGeneratedSalt);
    }
    else
    {
        memcpy(p->pSalt, pSalt, cbSalt);
        p->cbSalt = cbSalt;
    }
    // Keep a record of how many bytes have been requested through getBytes
    // so that we don't return the same bytes twice.
    p->bytesAlreadyGotten = 0;

    return p; // Malloc'd structure. It is the responsibility of the caller to free this when no longer needed
}

uint8_t *Rfc2898DeriveBytes_GetSalt(tRfc2898DeriveBytes *p, size_t *pcbSalt)
{
    if (!p)
    {
        app_tracef("ERROR: Parameter error. pRfc2898DeriveBytes is NULL");
        return NULL;
    }
    if (!pcbSalt)
    {
        app_tracef("ERROR: Parameter error. pcbSalt is NULL");
        return NULL;
    }
    *pcbSalt = p->cbSalt;

    return p->pSalt;  // Returns a pointer into the caller's own tRfc2898DeriveBytes structure
}

uint8_t *Rfc2898DeriveBytes_GetBytes(tRfc2898DeriveBytes *p, uint32_t byteCount )
{
    // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes.getbytes?view=netcore-3.1
    // Says...
    // Repeated calls to this method will not generate the same key;
    // instead, appending two calls of the GetBytes method with a [byteCount] parameter value of 20 is
    // the equivalent of calling the GetBytes method once with a [byteCount] parameter value of 40.

    // This is was not true for this implementation, which was copied from the XQMsg CPP api
    // but is now fixed here with the addition of bytesAlreadyGotten and associated code.
    // TODO - this needs to be fixed in the CPP api

    int rc;

    if (!p)
    {
        app_tracef("ERROR: Parameter error. pRfc2898DeriveBytes is NULL");
        return NULL;
    }

    // Allocate enough storage for all of the previously requested bytes, and a chunk of new bytes
    size_t bytesToGetFromPBKDF2 = p->bytesAlreadyGotten + byteCount;
    uint8_t *pBigBuffer = malloc (bytesToGetFromPBKDF2);
    if (pBigBuffer == NULL)
    {
        app_tracef("ERROR: malloc of pBigBuffer failed");
        return NULL;
    }

    rc = PKCS5_PBKDF2_HMAC( (const char*)p->pSecret,
                            (int)p->cbSecret,
                            p->pSalt,
                            (int)p->cbSalt,
                            PKCS5_PBKDF2_HMAC_ITERATIONS,
                            EVP_sha1(),
                            (int)bytesToGetFromPBKDF2,  // Get all of the previous bytes, and a chunk of new bytes
                            pBigBuffer );
    if (rc != 1)
    {
        app_tracef("ERROR: PKCS5_PBKDF2_HMAC failed with error %d", rc);
        free(pBigBuffer);
        return NULL;
    }

    // Create a new buffer of the size requested, and copy in the trailing "new chunk" of data
    uint8_t *pResultBuffer = malloc (byteCount);
    if (pResultBuffer == NULL)
    {
        app_tracef("ERROR: malloc of pResultBuffer failed");
        free(pBigBuffer);
        return NULL;
    }
    memcpy(pResultBuffer, pBigBuffer+p->bytesAlreadyGotten, byteCount);
    // Increase the number of bytes returned so that we don't return them again on a future call to GetBytes().
    p->bytesAlreadyGotten += byteCount;
    free(pBigBuffer);

    return pResultBuffer; // Malloc'd buffer. It is the responsibility of the caller to free this when no longer needed
}

#define INCLUDE_KNOWN_ANSWER_TESTS
#ifdef INCLUDE_KNOWN_ANSWER_TESTS
//https://stackoverflow.com/questions/9771212/how-to-use-pkcs5-pbkdf2-hmac-sha1

bool PBKDF2_KAT_verification(void)
{
    // Our mission:
    //    Password: "password"
    //    Salt: "salt"
    //    Iterations: 1
    //    Bytes requested: 20
    //    Expected Result: 0c60c80f961f0e71f3a9b524af6012062fe037a6

    //const int KEY_LEN     = 32;
    const int KEK_KEY_LEN = 20;
    size_t i;
    unsigned char *pActualResult;
    int rc;
    bool errorsFound = false;

    const char    password_value[]    = "password";
    unsigned char salt_value[]        = {'s','a','l','t'};
    const int     numberOfIterations  = 1;
    unsigned char expectedResult[]    = {0x0c,0x60,0xc8,0x0f,0x96,0x1f,0x0e,0x71,0xf3,0xa9,0xb5,0x24,0xaf,0x60,0x12,0x06,0x2f,0xe0,0x37,0xa6};

    pActualResult = (unsigned char *) malloc(sizeof(unsigned char)*KEK_KEY_LEN);
    if (!pActualResult)
    {
        app_tracef("[ibrand-service] ERROR: malloc failure");
        return false;
    }

    fprintf(stderr, "Password: %s\n", password_value);
    fprintf(stderr, "Iterations: %d\n", numberOfIterations);
    fprintf(stderr, "Salt: ");
    for(i=0;i<sizeof(salt_value);i++)
    {
        fprintf(stderr, "%02x", salt_value[i]);
    }
    fprintf(stderr, "\n");

    rc = PKCS5_PBKDF2_HMAC_SHA1(password_value, strlen(password_value), salt_value, sizeof(salt_value), numberOfIterations, KEK_KEY_LEN, pActualResult);
    if ( rc == 0 )
    {
        app_tracef("[ibrand-service] ERROR: PKCS5_PBKDF2_HMAC_SHA1 failed");
        free(pActualResult);
        return false;
    }

    errorsFound = false;
    fprintf(stderr, "ExpectedResult: ");
    for (int ii=0;ii<KEK_KEY_LEN;ii++)
    {
        fprintf(stderr, "%02X", expectedResult[ii]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "  ActualResult: ");
    for (int ii=0;ii<KEK_KEY_LEN;ii++)
    {
        fprintf(stderr, "%02X", pActualResult[ii]);
        if (pActualResult[ii] != expectedResult[ii])
        {
            errorsFound = true;
        }
    }
    fprintf(stderr, "\n");

    if (errorsFound)
    {
        app_tracef("[ibrand-service] ERROR: PKCS5_PBKDF2_HMAC_SHA1 Failed");
    }
    else
    {
        fprintf(stdout, "[ibrand-service] INFO: PKCS5_PBKDF2_HMAC_SHA1 Successful\n");
    }

    free(pActualResult);
    return true;
}

// Results...
// gcc pkcs5.c -o pkcs5 -g -lcrypto -Wall
// ./pkcs5
//   Password: password
//   Iterations: 1
//   Salt: 73616c74
//   ActualResult: 0c60c80f961f0e71f3a9b524af6012062fe037a6
//   ErrorsFound = false

#endif // INCLUDE_KNOWN_ANSWER_TESTS
