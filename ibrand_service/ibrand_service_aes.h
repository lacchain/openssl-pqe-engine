
// ibrand_service_aes.h
// Password-Based Key Derivation Function: PBKDF2

#ifndef _INCLUDE_IBRAND_SERVICE_AES_H_
#define _INCLUDE_IBRAND_SERVICE_AES_H_

#include <stdint.h> // For uint8_t etc

#include "../ibrand_common/my_utilslib.h" // For tLSTRING
#include "ibrand_service.h" // For tIB_INSTANCEDATA

extern int AESDecryptBytes(uint8_t *pIBCryptMessage,
                           size_t cbIBCryptMessage,
                           size_t cbSignificantData,
                           uint8_t *pSharedSecret,
                           size_t cbSharedSecret,
                           unsigned int saltSize,
                           uint8_t **ppDecryptedData,
                           size_t *pcbDecryptedData);

extern int AESDecryptPackage(tIB_INSTANCEDATA *pIBRand,
                             tLSTRING *pSourceBuffer,
                             tLSTRING *pDestBuffer,
                             size_t expectedSize,
                             bool hasHeader);

extern int testSymmetricEncryption(void);

#endif // _INCLUDE_IBRAND_SERVICE_AES_H_
