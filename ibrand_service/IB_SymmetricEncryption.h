
// IB_SymmetricEncryption.h
// Password-Based Key Derivation Function: PBKDF2

#ifndef _INCLUDE_IB_SYMMETRICENCRYPTION_H_
#define _INCLUDE_IB_SYMMETRICENCRYPTION_H_

#include "RFC2898DeriveBytes.h"

extern int AESDecryptBytes(uint8_t *pIBCryptMessage, size_t cbIBCryptMessage, uint8_t *pSharedSecret, size_t cbSharedSecret, unsigned int saltSize, uint8_t **ppDecryptedData, size_t *pcbDecryptedData);
extern int testSymmetricEncryption(void);

#endif // _INCLUDE_IB_SYMMETRICENCRYPTION_H_
