
// RFC2898DeriveBytes.h
// Password-Based Key Derivation Function: PBKDF2
// This wrapper: JGilmore 20-Jul-2020


#ifndef _INCLUDE_RFC2898DERIVEBYTES_H_
#define _INCLUDE_RFC2898DERIVEBYTES_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>


//typedef unsigned char  bool;
// typedef signed char    int8_t;
// typedef signed short   int16_t;
// typedef signed long    int32_t;
// typedef unsigned char  uint8_t;
// typedef unsigned short uint16_t;
// typedef unsigned long  uint32_t;

//#define true 1
//#define false 0
//#define TRUE 1
//#define FALSE 0

#define SECRET_MAXSIZE 256
#define SALT_MAXSIZE 32
typedef struct tagRfc2898DeriveBytes
{
    uint8_t pSecret[SECRET_MAXSIZE];
    uint8_t pSalt[SALT_MAXSIZE];
    size_t cbSecret;
    size_t cbSalt;
    size_t bytesAlreadyGotten;
} tRfc2898DeriveBytes;

extern tRfc2898DeriveBytes *Rfc2898DeriveBytes_Init(const uint8_t *pSecret, uint32_t cbSecret, const uint8_t *pSalt, uint32_t cbSalt); // Returns a malloc'd structure. It is the responsibility of the caller to free this when no longer needed
extern uint8_t *Rfc2898DeriveBytes_GetSalt(tRfc2898DeriveBytes *p, size_t *pcbSalt);      // Returns a pointer into the caller's own tRfc2898DeriveBytes structure
extern uint8_t *Rfc2898DeriveBytes_GetBytes(tRfc2898DeriveBytes *p, uint32_t byteCount ); // Returns a malloc'd buffer. It is the responsibility of the caller to free this when no longer needed
extern bool PBKDF2_KAT_verification(void);

#endif // _INCLUDE_RFC2898DERIVEBYTES_H_
