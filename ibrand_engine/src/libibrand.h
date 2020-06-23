#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <limits.h>
#elif !defined(_WIN32)
#include <linux/limits.h>
#endif
#if !defined(_WIN32)
#include <ftdi.h>
#endif
#include <time.h>

// The FT240X has a 512 byte buffer.  Must be multiple of 64
// We also write this in one go to the Keccak sponge, which is at most 1600 bits
#define BUFLEN 512u

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_WIN32)
struct ibrand_context {
    struct ftdi_context ftdic;
    uint32_t entropyThisTime;
    const char *message;
    bool errorFlag;
    //uint8_t keccakState[KeccakPermutationSizeInBytes];

    // used in multiplier mode to keep track of bytes to be put out
    uint32_t bytesGiven;
    uint32_t bytesWritten;
};

typedef struct _ibrand_devlist_node_t ibrand_devlist_node_t;
struct _ibrand_devlist_node_t {
    char manufacturer[128];
    char description[128];
    char serial[128];
    ibrand_devlist_node_t *next;
};

/*
 * returns a struct of ibrand_devlist_node listing all connected FTDI FT240 devices by their USB descriptors
 *
 * parameters:
 *  - message: pointer for error message
 *
 *  returns: NULL when none found or ibrand_devlist_node
 */
ibrand_devlist_node_t* listUSBDevices(const char **message);

/*
 * initialize the Infinite Noise TRNG - must be called once before readData() works
 *
 * parameters:
 *  - context: pointer to ibrand_context struct
 *  - serial: optional serial number of the device (NULL)
 *  - keccak: initialize Keccak sponge (required to use readData with raw=false)
 *  - debug: debug flag
 * returns: boolean success indicator (0=success)
*/
bool initIBRand(struct ibrand_context *context, char *serial, bool keccak, bool debug);


/*
 * deinitialize the Infinite Noise TRNG
 *
 * parameters:
 *  - context: pointer to ibrand_context struct
*/
void deinitIBRand(struct ibrand_context *context);

/*
 * Reads some bytes from the TRNG and stores them in the "result" byte array.
 * The array has to be of sufficient size. Please refer to the example programs.
 * (64 byte for normal operation or 128byte for multiplier mode)
 *
 * After every read operation, the ibrand_context's errorFlag must be checked,
 * and the data from this call has to be discarded when it returns true!
 *
 * Detailed error messages can then be found in context->message.
 *
 * parameters:
 *  - context: ibrand_context struct with device pointer and state variables
 *  - result: pointer to byte array to store the result
 *  - raw: boolean flag for raw or whitened output
 *  - outputMultiplier: only used for whitened output
 *
 * returns: number of bytes written to the byte-array
*/
uint32_t readData(struct ibrand_context *context, uint8_t *result, bool raw, uint32_t outputMultiplier);

#ifdef __cplusplus
}
#endif

#endif
