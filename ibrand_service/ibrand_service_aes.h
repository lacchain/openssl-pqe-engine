
// ibrand_service_aes.h
// Password-Based Key Derivation Function: PBKDF2

#ifndef _INCLUDE_IBRAND_SERVICE_AES_H_
#define _INCLUDE_IBRAND_SERVICE_AES_H_

#include <stdint.h> // For uint8_t etc

#include "../ibrand_common/my_utilslib.h" // For tLSTRING
#include "ibrand_service.h" // For tIB_INSTANCEDATA

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_AES_FLOOR 18400
#define ERC_AES_NOENT_SHARED_SECRET_NOT_FOUND 18410
#define ERC_AES_NOENT_CIPHERTEXT_NOT_FOUND    18420
#define ERC_AES_BASE64_DECODE_FAILURE         18430
#define ERC_AES_HEADER_SIZE_ERROR             18440
#define ERC_AES_NOMEM_FOR_SALT                18450
#define ERC_AES_NOMEM_FOR_CIPHERTEXT          18460
#define ERC_AES_RFC2898_INIT_FAILED           18470
#define ERC_AES_RFC2898_GETKEY_FAILED         18480
#define ERC_AES_RFC2898_GETIV_FAILED          18490
#define ERC_AES_SET_DECRYPT_KEY_FAILED        18500
#define ERC_AES_NOMEM_FOR_RAWDATA             18510

extern tERRORCODE AESDecryptBytes(uint8_t *pIBCryptMessage,
                           size_t cbIBCryptMessage,
                           size_t cbSignificantData,
                           uint8_t *pSharedSecret,
                           size_t cbSharedSecret,
                           unsigned int saltSize,
                           uint8_t **ppDecryptedData,
                           size_t *pcbDecryptedData);

extern tERRORCODE AESDecryptPackage(tIB_INSTANCEDATA *pIBRand,
                             tLSTRING *pSourceBuffer,
                             tLSTRING *pDestBuffer,
                             size_t expectedSize,
                             bool hasHeader);

extern int testSymmetricEncryption(void);

#endif // _INCLUDE_IBRAND_SERVICE_AES_H_
