
// Password-Based Key Derivation Function: PBKDF2

#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "my_utilslib.h"
#include "RFC2898DeriveBytes.h"
#include "IB_SymmetricEncryption.h"

int main(int argc, char *argv[])
{
    int rc;

    UNUSED_PARAM(argc);
    UNUSED_PARAM(argv);

    ///////////////////////////////////////////
    // Self tests and Known Answer Tests
    ///////////////////////////////////////////
    fprintf(stderr, "==================================== RFC2898DeriveBytes (PBKDF2) KAT Tests\n");
    rc = PBKDF2_KAT_verification();
    if (rc == false)
    {
        fprintf(stderr, "PBKDF2_KAT_verification failed\n");
        return -1;
    }

    fprintf(stderr, "==================================== AES Encryption/Decryption Tests with derived keys/IV\n");
    fprintf(stderr, "PLEASE NOTE: These tests are currently failing because the data that it is testing against\n");
    fprintf(stderr, "is based on the deriveFunction doing only 1000 iterations. This has since been increased.\n");
    fprintf(stderr, "To fix the tests, the test data would need to be regenerated with this large value.\n");
    fprintf(stderr, "Search for PKCS5_PBKDF2_HMAC_ITERATIONS\n");
    int failed_tests2 = testSymmetricEncryption();
    if (failed_tests2 > 0)
    {
        fprintf(stderr, "testSymmetricEncryption failed\n");
        return -1;
    }

    return 0;
}
