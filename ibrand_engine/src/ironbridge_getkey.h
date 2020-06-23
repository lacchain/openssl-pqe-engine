



#ifndef __INCLUDE_IRONBRIDGE_GETKEY__
#define __INCLUDE_IRONBRIDGE_GETKEY__

extern void * ironbridge_getkey_initialise(char *pBaseUrl, char *pUsername, char *pPassword);
extern int ironbridge_getkey(void *hIronBridgeRand, unsigned int numberOfBits, char **ppData, unsigned int *pcbData);
extern const char *ironbridge_getLastErrorMessage(void *hIronBridgeRand);
extern void ironbridge_getkey_finalise(void *hIronBridgeRand);

extern char*          base64_encode(const unsigned char *data, size_t input_length, size_t *poutput_length);
extern unsigned char* base64_decode(const char *data, size_t input_length, size_t *poutput_length);

#endif // __INCLUDE_IRONBRIDGE_GETKEY__
