#ifndef PQCLEAN_SNTRUP857_CLEAN_API_H
#define PQCLEAN_SNTRUP857_CLEAN_API_H



#define PQCLEAN_SNTRUP857_CLEAN_CRYPTO_ALGNAME "sntrup857"

#define PQCLEAN_SNTRUP857_CLEAN_CRYPTO_SECRETKEYBYTES 1999
#define PQCLEAN_SNTRUP857_CLEAN_CRYPTO_PUBLICKEYBYTES 1322
#define PQCLEAN_SNTRUP857_CLEAN_CRYPTO_CIPHERTEXTBYTES 1184
#define PQCLEAN_SNTRUP857_CLEAN_CRYPTO_BYTES 32

int PQCLEAN_SNTRUP857_CLEAN_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int PQCLEAN_SNTRUP857_CLEAN_crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk);
int PQCLEAN_SNTRUP857_CLEAN_crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk);
#endif
