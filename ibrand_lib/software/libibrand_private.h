
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <limits.h>
#elif !defined(_WIN32)
#include <linux/limits.h>
#endif
#include <time.h>
#include "libibrand.h"

#define IBRAND_VENDOR_ID 0xFFFF
#define IBRAND_PRODUCT_ID 0xFFFF

// Required accuracy of estimated vs measured entropy in health monitor
#define INM_ACCURACY 1.03

// This is the maximum time we allow to pass to perform the I/O operations, since long
// delays can reduce entropy from the INM.
#define MAX_MICROSEC_FOR_SAMPLES 200000u // 5000u

#define BITMODE_SYNCBB 0x4

// This defines which pins on the FT240X are used
#define COMP1 1u
#define COMP2 4u
#define SWEN1 2u
#define SWEN2 0u

// The remaining 8 bits are driven with 0 .. 15 to help track the cause of misfires
#define ADDR0 3u
#define ADDR1 5u
#define ADDR2 6u
#define ADDR3 7u

// All data bus bits of the FT240X are outputs, except COMP1 and COMP2
#define MASK (0xffu & ~(1u << COMP1) & ~(1u << COMP2))

#if !defined(_WIN32)

struct timespec;
extern double diffTime(struct timespec *start, struct timespec *end);
extern bool outputBytes(uint8_t *bytes, uint32_t length, uint32_t entropy, bool writeDevRandom, const char **message);
extern uint32_t processBytes(uint8_t *pBytes, size_t   cbBytes, uint8_t *pResult, size_t cbResult);

#endif
