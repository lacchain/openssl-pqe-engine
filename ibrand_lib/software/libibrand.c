/* Library for the Infinite Noise Multiplier USB stick */

#define RANDSRC_USB    0
#define RANDSRC_FILE   1
#define IB_SOURCE_OF_RANDOMNESS RANDSRC_FILE

#define CONFIG_HARDCODED 1
#define CONFIG_SIMPLE    2
#define CONFIG_JSON      3
#define USE_CONFIG CONFIG_JSON

#define DBGBIT_STATUS  0
#define DBGBIT_CONFIG  1
#define DBGBIT_AUTH    2
#define DBGBIT_DATA    3
#define DBGBIT_CURL    4
#define DBGBIT_SPARE5  5
#define DBGBIT_SPARE6  6
#define DBGBIT_SPARE7  7


// Required to include clock_gettime
#define _POSIX_C_SOURCE 200809L

#define IBRAND_VENDOR_ID 0xFFFF
#define IBRAND_PRODUCT_ID 0xFFFF


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <syslog.h>

//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
#include <ftdi.h>
#include "libibrand_private.h"
#include "KeccakF-1600-interface.h"
//#endif

#include "my_utilslib.h"

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__FreeBSD__)
#include <fcntl.h>
#endif

#define MINIMUM(a,b) (a<b?a:b)
#define MAXIMUM(a,b) (a>b?a:b)

#define FILELOCK_LOGLEVEL 0x00  // 0x01 is stdout, 0x02 is syslog

uint8_t keccakState[KeccakPermutationSizeInBytes] = {0};
uint8_t outBuf[BUFLEN] = {0};

#define UNUSED_VAR(x)  (void)(x);

typedef struct tagIB_INSTANCEDATA
{
    char          szStorageType[16];                // "FILE";
    char          szStorageDataFormat[16];          // RAW, BASE64, HEX
    char          szStorageFilename[_MAX_PATH];     // "/var/lib/ibrand/ibrand_data.bin";
    char          szStorageLockfilePath[_MAX_PATH]; // "/tmp";
    long          storageHighWaterMark;             // 1038336; // 1MB
    long          storageLowWaterMark;              // 102400; // 100KB
    unsigned char  fVerbose;                        // bit 0=general, bit1=config bit2=auth, bit3=data, bit4=curl:

    char          szConfigFilename[_MAX_PATH];      //  "/usr/local/ssl/ibrand.cnf"
} tIB_INSTANCEDATA;

#if (USE_CONFIG==CONFIG_JSON)
tIB_INSTANCEDATA *pIBRand = NULL;
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_INSTANCEDATA *pIBRand);
static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand);
static void PrintConfig(tIB_INSTANCEDATA *pIBRand);
#endif

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
bool initIBRand(struct ibrand_context *context, char *serial, bool keccak, bool debug)
{
    context->message = "";
    context->entropyThisTime = 0;
    context->errorFlag = false;
    context->bytesGiven = 0;
    context->bytesWritten = 0;


//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
//    printf("initIBRand: IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB\n");
//#elif (IB_SOURCE_OF_RANDOMNESS == RANDSRC_FILE)
//    printf("initIBRand: IB_SOURCE_OF_RANDOMNESS == RANDSRC_FILE\n");
//#endif

    prepareOutputBuffer();

    // initialize health check
    if (!inmHealthCheckStart(PREDICTION_BITS, DESIGN_K, debug))
    {
        context->message = "Can't initialize health checker";
        return false;
    }

#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
    // initialize USB
    if (!initializeUSB(&context->ftdic, &context->message, serial))
    {
        // Sometimes have to do it twice - not sure why
        if (!initializeUSB(&context->ftdic, &context->message, serial))
        {
            return false;
        }
    }
#else // IB_SOURCE_OF_RANDOMNESS
    UNUSED_VAR(context);
    UNUSED_VAR(serial);

#if (USE_CONFIG==CONFIG_JSON)
    int rc;
    // =========================================================================
    // Create instance storage
    // =========================================================================
    pIBRand = malloc(sizeof(tIB_INSTANCEDATA));
    if (!pIBRand)
    {
        fprintf(stderr, "FATAL: Failed to allocate memory for local storage. Aborting.");
        exit(EXIT_FAILURE);
    }
    memset(pIBRand, 0, sizeof(tIB_INSTANCEDATA));

    char *tempPtr;
    rc = my_getFilenameFromEnvVar("IBRAND_CONF", &tempPtr);
    if (rc==0)
    {
        my_strlcpy(pIBRand->szConfigFilename, tempPtr, sizeof(pIBRand->szConfigFilename));
        free(tempPtr);
    }
    if (strlen(pIBRand->szConfigFilename) == 0)
    {
        fprintf(stderr, "FATAL: Configuration not specified, neither on commandline nor via an environment variable.\n");
        free(pIBRand);
        exit(EXIT_FAILURE);
    }

    app_trace_openlog("ibrand_openssl", LOG_PID|LOG_CONS|LOG_PERROR, LOG_USER );

    rc = ReadConfig(pIBRand->szConfigFilename, pIBRand);
    if (rc != 0)
    {
        fprintf(stderr, "FATAL: Configuration error. rc=%d\n", rc);
        app_tracef("FATAL: Configuration error. Aborting. rc=%d", rc);
        app_trace_closelog();
        free(pIBRand);
        exit(EXIT_FAILURE);
    }
    if (TEST_BIT(pIBRand->fVerbose,DBGBIT_CONFIG))
    {
        PrintConfig(pIBRand);
    }

#endif // (USE_CONFIG==CONFIG_JSON)

#endif // IB_SOURCE_OF_RANDOMNESS

    // initialize keccak
    if (keccak)
    {
        KeccakInitialize();
        KeccakInitializeState(keccakState);
    }

    // let healthcheck collect some data
    uint32_t maxWarmupRounds = 5000;
    uint32_t warmupRounds = 0;

    //bool errorFlag = false;
    while (!inmHealthCheckOkToUseData())
    {
        readData(context, NULL, true, 1);
        warmupRounds++;
    }

    if (warmupRounds > maxWarmupRounds)
    {
        context->message = "Unable to collect enough entropy to initialize health checker.";
        return false;
    }
    return true;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
void deinitIBRand(struct ibrand_context *context)
{
    inmHealthCheckStop();
#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
    ftdi_usb_close(&context->ftdic);
    ftdi_deinit(&context->ftdic);
#else // IB_SOURCE_OF_RANDOMNESS
    UNUSED_VAR(context);
#endif // IB_SOURCE_OF_RANDOMNESS
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
void prepareOutputBuffer(void)
{
    uint32_t i;

    // Endless loop: set SW1EN and SW2EN alternately
    for (i = 0u; i < BUFLEN; i += 2)
    {
        // Alternate Ph1 and Ph2
        outBuf[i] = (1 << SWEN1);
        outBuf[i + 1] = (1 << SWEN2);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Extract the INM output from the data received.  Basically, either COMP1 or COMP2
// changes, not both, so alternate reading bits from them.  We get 1 INM bit of output
// per byte read.  Feed bits from the INM to the health checker.  Return the expected
// bits of entropy.
////////////////////////////////////////////////////////////////////////////////
uint32_t extractBytes(uint8_t *bytes, uint32_t length, uint8_t *inBuf, const char **message, bool *errorFlag)
{
    inmClearEntropyLevel();
    uint32_t i;

    for (i = 0u; i < length; i++)
    {
        uint32_t j;
        uint8_t byte = 0u;
        for (j = 0u; j < 8u; j++)
        {
            uint8_t val = inBuf[i * 8u + j];
            uint8_t evenBit = (val >> COMP2) & 1u;
            uint8_t oddBit = (val >> COMP1) & 1u;
            bool even = j & 1u; // Use the even bit if j is odd
            uint8_t bit = even ? evenBit : oddBit;
            byte = (byte << 1u) | bit;

            // This is a good place to feed the bit from the INM to the health checker.
            if (!inmHealthCheckAddBit(evenBit, oddBit, even))
            {
                *message = "Health check of Infinite Noise Multiplier failed!";
                *errorFlag = true;
                return 0;
            }
        }
        bytes[i] = byte;
    }
    return inmGetEntropyLevel();
}

////////////////////////////////////////////////////////////////////////////////
// Whiten the output, if requested, with a Keccak sponge. Output bytes only if the health
// checker says it's OK.  Using outputMultiplier > 1 is a nice way to generate a lot more
// cryptographically secure pseudo-random data than the INM generates.  If
// outputMultiplier is 0, we output only as many bits as we measure in entropy.
// This allows a user to generate hundreds of MiB per second if needed, for use
// as cryptographic keys.
////////////////////////////////////////////////////////////////////////////////
uint32_t processBytes(uint8_t *bytes,
                      uint8_t *result,
                      uint32_t *entropy,
                      uint32_t *bytesGiven,
                      uint32_t *bytesWritten,
                      bool raw,
                      uint32_t outputMultiplier)
{
    // Use the lower of the measured entropy and the provable lower bound on
    // average entropy.
    if (*entropy > inmExpectedEntropyPerBit * BUFLEN / INM_ACCURACY)
    {
        *entropy = inmExpectedEntropyPerBit * BUFLEN / INM_ACCURACY;
    }
    if (raw)
    {
        // In raw mode, we just output raw data from the INM.
        if (result != NULL)
        {
            memcpy(result, bytes, BUFLEN / 8u * sizeof(uint8_t));
        }
        return BUFLEN / 8u;
    }

    // Note that BUFLEN has to be less than 1600 by enough to make the sponge secure,
    // since outputting all 1600 bits would tell an attacker the Keccak state, allowing
    // him to predict any further output, when outputMultiplier > 1, until the next call
    // to processBytes.  All 512 bits are absorbed before squeezing data out to ensure that
    // we instantly recover (reseed) from a state compromise, which is when an attacker
    // gets a snapshot of the keccak state.  BUFLEN must be a multiple of 64, since
    // Keccak-1600 uses 64-bit "lanes".
    uint8_t resultSize;
    if (outputMultiplier <= 2)
    {
        resultSize = 64u;
    }
    else
    {
        resultSize = 128u;
    }

    uint8_t dataOut[resultSize];
    KeccakAbsorb(keccakState, bytes, BUFLEN / 64u);

    if (outputMultiplier == 0u)
    {
        // Output all the bytes of entropy we have
        KeccakExtract(keccakState, dataOut, (*entropy + 63u) / 64u);
        if (result != NULL)
        {
            memcpy(result, dataOut, *entropy / 8u * sizeof(uint8_t));
        }
        return *entropy / 8u;
    }

    // Output 256*outputMultipler bits (in chunks of 1024)
    // only the first 1024 now,
    if (*bytesGiven == 0u)
    {
        *bytesGiven = outputMultiplier * 256u / 8u;
        *bytesWritten = 0u;

        // Output up to 1024 bits at a time.
        uint32_t bytesToWrite = 1024u / 8u;
        if (bytesToWrite > *bytesGiven)
        {
            bytesToWrite = *bytesGiven;
        }

        KeccakExtract(keccakState, result, bytesToWrite / 8u);
        KeccakPermutation(keccakState);
        *bytesWritten = bytesToWrite;
        *bytesGiven -= bytesToWrite;
    }
    return *bytesWritten;
}

////////////////////////////////////////////////////////////////////////////////
// Return the difference in the times as a double in microseconds.
////////////////////////////////////////////////////////////////////////////////
double diffTime(struct timespec *start, struct timespec *end)
{
    uint32_t seconds = end->tv_sec - start->tv_sec;
    int32_t nanoseconds = end->tv_nsec - start->tv_nsec;
    return seconds * 1.0e6 + nanoseconds / 1000.0;
}

////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
bool isSuperUser(void)
{
    return (geteuid() == 0);
}

//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
////////////////////////////////////////////////////////////////////////////////
// let's do it recursive, because if sth. fails we can easily wipe the malloc()
////////////////////////////////////////////////////////////////////////////////
ibrand_devlist_node_t *inf_get_devstrings(struct ftdi_context *ftdic,
                                            struct ftdi_device_list *curdev,
                                            const char **message,
                                            ibrand_devlist_node_t *bgn,
                                            ibrand_devlist_node_t *end)
{
    if (curdev != NULL)
    {
        ibrand_devlist_node_t *cur;
        cur = (ibrand_devlist_node_t *)malloc(sizeof(ibrand_devlist_node_t));
        cur->next = NULL;
//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
        int rc = ftdi_usb_get_strings(ftdic, curdev->dev,
                                      cur->manufacturer, sizeof(cur->manufacturer),
                                      cur->description, sizeof(cur->description),
                                      cur->serial, sizeof(cur->serial));
//#else
//#endif
        if (rc < 0)
        {
            *message = ftdi_get_error_string(ftdic);
            free(cur);
            return NULL;
        }
        else
        {
            // in case bgn is NULL, then implicitly end is NULL, also the other way around
            if (bgn == NULL)
            {
                bgn = cur;
            }
            else
            {
                end->next = cur;
            }
            ibrand_devlist_node_t *ret;
            ret = inf_get_devstrings(ftdic, curdev->next, message, bgn, cur);
            // a next dev triggered issue? -> wipe current
            if (ret == NULL)
            {
                free(cur);
            }
            return ret;
        }
    }
    return bgn;
}
//#endif

//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
////////////////////////////////////////////////////////////////////////////////
// Return a list of all infinite noise multipliers found.
////////////////////////////////////////////////////////////////////////////////
ibrand_devlist_node_t *listUSBDevices(const char **message)
{
    struct ftdi_context ftdic;
    if (ftdi_init(&ftdic) < 0)
    {
        *message = "ERROR 101: Failed to init";
        return NULL;
    }

    ibrand_devlist_node_t *retlist = NULL;
    struct ftdi_device_list *devlist = NULL;
    if (ftdi_usb_find_all(&ftdic, &devlist, IBRAND_VENDOR_ID, IBRAND_PRODUCT_ID) < 0 || devlist == NULL)
    {
        if (!isSuperUser())
        {
            *message = "ERROR 102: Can't find Infinite Noise Multiplier.  Try running as super user?";
        }
        else
        {
            *message = "ERROR 103: Can't find Infinite Noise Multiplier.";
        }
    }
    else
    {
        retlist = inf_get_devstrings(&ftdic, devlist, message, NULL, NULL);
        ftdi_list_free2(devlist);
    }

    ftdi_deinit(&ftdic);
    return retlist;
}
//#endif // IB_SOURCE_OF_RANDOMNESS

//#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
////////////////////////////////////////////////////////////////////////////////
// Initialize the Infinite Noise Multiplier USB interface.
////////////////////////////////////////////////////////////////////////////////
bool initializeUSB(struct ftdi_context *ftdic, const char **message, char *serial)
{
    ftdi_init(ftdic);
    struct ftdi_device_list *devlist;

    // search devices
    int rc = ftdi_usb_find_all(ftdic, &devlist, IBRAND_VENDOR_ID, IBRAND_PRODUCT_ID);
    if (rc < 0)
    {
        *message = "ERROR 104: Can't find Infinite Noise Multiplier";
        return false;
    }
    ftdi_list_free2(devlist);

    // only one found, or no serial given
    if (serial == NULL)
    {
        // more than one found AND no serial given
        if (rc >= 2)
        {
            *message = "ERROR 105: Multiple IBRand TRNGs found and serial not specified, using the first one!";
        }
        if (ftdi_usb_open(ftdic, IBRAND_VENDOR_ID, IBRAND_PRODUCT_ID) < 0)
        {
            if (!isSuperUser())
            {
                *message = "ERROR 106: Can't open Infinite Noise Multiplier. Try running as super user?";
            }
            else
            {
#ifdef LINUX
                *message = "ERROR 107: Can't open Infinite Noise Multiplier.";
#endif
#if defined(__APPLE__)

                *message = "ERROR 108: Can't open Infinite Noise Multiplier. sudo kextunload -b com.FTDI.driver.FTDIUSBSerialDriver ? sudo kextunload -b  com.apple.driver.AppleUSBFTDI ?";
#endif
            }
#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
            return false;
#endif
        }
    }
    else
    {
        // serial specified
        if (ftdi_usb_open_desc(ftdic, IBRAND_VENDOR_ID, IBRAND_PRODUCT_ID, NULL, serial) < 0)
        {
            if (!isSuperUser())
            {
                *message = "ERROR 109: Can't find Infinite Noise Multiplier. Try running as super user?";
            }
            else
            {
                *message = "ERROR 110: Can't find Infinite Noise Multiplier with given serial";
            }
            return false;
        }
    }

#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_USB)
    // Set high baud rate
    switch (ftdi_set_baudrate(ftdic, 30000))
    {
    case -1:
        *message = "ERROR 110.1: Invalid baud rate";
        return false;
    case -2:
        *message = "ERROR 110.2: Setting baud rate failed";
        return false;
    case -3:
        *message = "ERROR 110.3: Infinite Noise Multiplier unavailable";
        return false;
    default:
        break;
    }

    switch (ftdi_set_bitmode(ftdic, MASK, BITMODE_SYNCBB))
    {
    case -1:
        *message = "ERROR 111: Can't enable bit-bang mode";
        return false;
    case -2:
        *message = "ERROR 112: Infinite Noise Multiplier unavailable\n";
        return false;
    default:
        break;
    }

    // Just test to see that we can write and read.
    uint8_t buf[64u] = {0};

    if (ftdi_write_data(ftdic, buf, sizeof(buf)) != sizeof(buf))
    {
        *message = "ERROR 113: USB write failed";
        return false;
    }
    if (ftdi_read_data(ftdic, buf, sizeof(buf)) != sizeof(buf))
    {
        *message = "ERROR 114: USB read failed";
        return false;
    }
#endif // IB_SOURCE_OF_RANDOMNESS
    return true;
}
//#endif // IB_SOURCE_OF_RANDOMNESS


////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
char *GetValueFromConfigFile(char *szEnvVariableWithFilename, char *szKey)
{
    const char *szConfigfilePath;
    FILE *fConfFile;
    char *szRetVal = NULL;

    szConfigfilePath = getenv(szEnvVariableWithFilename);
    if (!szConfigfilePath)
    {
        printf("ERROR: Cannot find environment variable: %s\n", szEnvVariableWithFilename);
        return NULL;
    }

    fConfFile = fopen(szConfigfilePath, "rt");
    if (fConfFile == NULL)
    {
        printf("ERROR: Cannot open config file: %s\n", szConfigfilePath);
        return NULL;
    }

    char line[1024] = {0};
    while (!feof(fConfFile))
    {
        memset(line, 0, 1024);
        char *ret = fgets(line, 1024, fConfFile);
        if (ret==NULL)
        {
            break; // EOF
        }
        if (line[0] == '#')
        {
            continue;
        }

        int len = strlen(line);
        char *pos = strchr(line, '=');
        if (pos == NULL)
        {
            continue;
        }
        char key[64] = {0};
        char val[64] = {0};

        int offset = 1;
        if (line[len-1] == '\n')
        {
            offset = 2;
        }

        strncpy(key, line, pos-line);
        strncpy(val, pos+1, line+len-offset-pos);

        //printf("INFO: Found Key:Value pair:  %s:%s\n", key, val);

        if (strcmp(key, szKey) == 0)
        {
            szRetVal = malloc(strlen(val+1));
            if (!szRetVal)
            {
                printf("ERROR: Out of memory\n");
                fclose(fConfFile);
                return NULL;
            }
            strcpy(szRetVal, val);
            break;
        }
    }
    if (!szRetVal)
    {
        printf("ERROR: Cannot find config key: %s\n", szKey);
    }
    fclose(fConfFile);
    return szRetVal;
}


////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////
uint32_t readData_Protected(struct ibrand_context *context, uint8_t *result, bool raw, uint32_t outputMultiplier);

uint32_t readData(struct ibrand_context *context, uint8_t *result, bool raw, uint32_t outputMultiplier)
{
    static int fReadDataIsBusy = 0;
    uint32_t rc;

    if (fReadDataIsBusy > 0)
    {
        context->message = "readData is busy";
        context->errorFlag = true;
        return 0;
    }

    fReadDataIsBusy++;
    rc = readData_Protected(context, result, raw, outputMultiplier);
    fReadDataIsBusy--;
    return rc;

}

uint32_t readData_Protected(struct ibrand_context *context, uint8_t *result, bool raw, uint32_t outputMultiplier)
{
    // check if data can be squeezed from the keccak sponge from previous state
    // (or we need to collect some new entropy to get bytesGiven >0)
    if (context->bytesGiven > 0u)
    {
        // squeeze the sponge!

        // Output up to 1024 bits at a time.
        uint32_t bytesToWrite = 1024u / 8u;

        if (bytesToWrite > context->bytesGiven)
        {
            bytesToWrite = context->bytesGiven;
        }

        KeccakExtract(keccakState, result, bytesToWrite / 8u);
        KeccakPermutation(keccakState);

        context->bytesWritten += bytesToWrite;
        context->bytesGiven -= bytesToWrite;
        return bytesToWrite;
    }
    else
    {
        // collect new entropy
        uint8_t inBuf[BUFLEN];
        struct timespec start;
        clock_gettime(CLOCK_REALTIME, &start);

#if (IB_SOURCE_OF_RANDOMNESS == RANDSRC_FILE)
        {
            FILE * fIBDatafile;
            char * szIBDatafilename = "/var/lib/ibrand/ibrand_data.bin";
            char * szLockfilePath = "/tmp";
            size_t filesize;
            size_t bytesToRead;
            size_t bytesRead;

#if (USE_CONFIG==CONFIG_HARDCODED)
            szIBDatafilename = "/var/lib/ibrand/ibrand_data.bin";
#elif (USE_CONFIG==CONFIG_SIMPLE)
            char * mallocedStorageFilename;

            // STORAGETYPE=FILE
            // STORAGEFILENAME=/var/lib/ibrand/ibrand_data.bin
            // STORAGEHIGHWATERMARK=1038336
            // STORAGELOWWATERMARK=102400

            mallocedStorageFilename = GetValueFromConfigFile("IBRAND_CONF","STORAGEFILENAME");
            if (mallocedStorageFilename)
            {
                szIBDatafilename = mallocedStorageFilename;
            }
#elif (USE_CONFIG==CONFIG_JSON)
            szIBDatafilename = pIBRand->szStorageFilename;
#endif // USE_CONFIG

            bytesToRead = sizeof(inBuf);

            my_waitForFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);

            // Open the file
            fIBDatafile = fopen(szIBDatafilename,"rb");
            if (fIBDatafile == NULL)
            {
                context->message = "ERROR: Unable to open IBDatafile";
                context->errorFlag = true;
                printf("%s - (%s)\n", context->message, szIBDatafilename);
#if (USE_CONFIG==CONFIG_SIMPLE)
                if (mallocedStorageFilename)
                {
                    free(mallocedStorageFilename);
                }
#endif
                my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);
                return 0;
            }
#if (USE_CONFIG==CONFIG_SIMPLE)
            if (mallocedStorageFilename)
            {
                free(mallocedStorageFilename);
            }
#endif
            // Ensure that there is enough data
            fseek (fIBDatafile, 0, SEEK_END);
            filesize = ftell(fIBDatafile);
            rewind(fIBDatafile);
            if (filesize < bytesToRead)
            {
                context->message = "ERROR: Insufficient data in IBDatafile";
                context->errorFlag = true;
                fclose(fIBDatafile);
                printf("%s - (requested=%lu, actual=%lu)\n", context->message, bytesToRead, filesize);
                my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);
                return 0;
            }

            // Read the data
            // Not ideal, but for now we will read from the end of the file, and then truncate what we have read.
            fseek (fIBDatafile, filesize - bytesToRead, SEEK_SET);
            bytesRead = fread(inBuf, sizeof(char), bytesToRead, fIBDatafile);
            if (bytesRead != bytesToRead)
            {
                context->message = "ERROR: Failed to read from IBDatafile";
                context->errorFlag = true;
                fclose(fIBDatafile);
                printf("%s - (requested=%lu, bytesRead=%ld)\n", context->message, bytesToRead, bytesRead );
                my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);
                return 0;
            }

            // ...and close the file
            fclose(fIBDatafile);

            // Then... remove the data we have just read.
            if (truncate(szIBDatafilename, filesize - bytesToRead) != 0)
            {
                context->message = "ERROR: Unable to remove the data from the file";
                context->errorFlag = true;
                my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);
                return 0;
            }
            my_releaseFileLock(szLockfilePath, szIBDatafilename, FILELOCK_LOGLEVEL);

            //printf(".");
        }
#endif // IB_SOURCE_OF_RANDOMNESS

        struct timespec end;
        clock_gettime(CLOCK_REALTIME, &end);
        uint32_t us = diffTime(&start, &end);

        if (us <= MAX_MICROSEC_FOR_SAMPLES)
        {
            uint8_t bytes[BUFLEN / 8u];
            context->errorFlag = 0;
            context->entropyThisTime = extractBytes(bytes, sizeof(bytes), inBuf, &context->message, &context->errorFlag);
            if (context->errorFlag)
            {
                // has context->message already been set?
                printf("ERROR: extractBytes set errorFlag: %d\n", context->errorFlag);
                return 0;
            }
            // Call health check and return bytes if OK
            if (inmHealthCheckOkToUseData() && inmEntropyOnTarget(context->entropyThisTime, BUFLEN))
            {
                uint32_t ret;
                ret = processBytes(bytes,
                                    result,
                                    &context->entropyThisTime,
                                    &context->bytesGiven,
                                    &context->bytesWritten,
                                    raw,
                                    outputMultiplier);
                //printf("INFO: processBytes returned %u\n", ret);
                return ret;
            }
            else
            {
                printf("ERROR: inmHealthCheckOkToUseData failed\n");
            }

        }
        else
        {
            // The maximum allowed time to perform the I/O operations was exceeded possibly causing reduced entropy.
            context->message = "ERROR: The time to acquire the data was exceeded resulting in possible reduced entropy.";
            context->errorFlag = true;
            printf("%s - (max=%u, actual=%u)\n", context->message, MAX_MICROSEC_FOR_SAMPLES, us );
            return 0;
        }
    }

    return 0;
}


#if (USE_CONFIG==CONFIG_JSON)
////////////////////////////////////////////////////////////////////////////////
// Config Top Level Functions
////////////////////////////////////////////////////////////////////////////////
static bool __ParseJsonConfig(const char *szJsonConfig, tIB_INSTANCEDATA *pIBRand)
{
    JSONObject *json2 = NULL;
    const int localConfigTracing = false;

    json2 = my_parseJSON(szJsonConfig);
    if (!json2)
    {
        app_tracef("ERROR: Failed to parse JSON string\n");
        return false;
    }

    for (int ii=0; ii<json2->count; ii++)
    {
        if (localConfigTracing)
            app_tracef("DEBUG: Found json item[%d] %s=%s\r\n", ii, json2->pairs[ii].key, (json2->pairs[ii].type == JSON_STRING)?(json2->pairs[ii].value->stringValue):"[JSON object]");

        if (strcmp(json2->pairs[ii].key,"AuthSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    // None of these items are interesting for us
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"CommsSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    // None of these items are interesting for us
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"StorageSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"STORAGETYPE")==0)
                    {
                        my_strlcpy(pIBRand->szStorageType, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageType));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEDATAFORMAT")==0)
                    {
                        my_strlcpy(pIBRand->szStorageDataFormat, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageDataFormat));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEFILENAME")==0)
                    {
                        my_strlcpy(pIBRand->szStorageFilename, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageFilename));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOCKFILEPATH")==0)
                    {
                        my_strlcpy(pIBRand->szStorageLockfilePath, childJson->pairs[jj].value->stringValue, sizeof(pIBRand->szStorageLockfilePath));
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGEHIGHWATERMARK")==0)
                    {
                        pIBRand->storageHighWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                    else if (strcmp(childJson->pairs[jj].key,"STORAGELOWWATERMARK")==0)
                    {
                        pIBRand->storageLowWaterMark = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
        else if (strcmp(json2->pairs[ii].key,"GeneralSettings") == 0 && json2->pairs[ii].type == JSON_OBJECT)
        {
            JSONObject *childJson = json2->pairs[ii].value->jsonObject;

            for (int jj=0; jj<childJson->count; jj++)
            {
                if (localConfigTracing)
                    app_tracef("DEBUG: Found json item[%d,%d] %s=%s\r\n", ii, jj, childJson->pairs[jj].key, (childJson->pairs[jj].type == JSON_STRING)?(childJson->pairs[jj].value->stringValue):"[JSON object]");

                if (childJson->pairs[jj].type == JSON_STRING)
                {
                    if (strcmp(childJson->pairs[jj].key,"LOGGING_VERBOSITY")==0)
                    {
                        pIBRand->fVerbose = atoi(childJson->pairs[jj].value->stringValue);
                    }
                }
            }
        }
    }

    my_freeJSONFromMemory(json2);
    return true;
}

static int ReadConfig(char *szConfigFilename, tIB_INSTANCEDATA *pIBRand)
{
    char *szJsonConfig;
    int rc;

    rc = my_readEntireConfigFileIntoMemory(szConfigFilename, &szJsonConfig);
    if (rc)
    {
        app_tracef("ERROR: Error %d reading JSON config from file: %s", rc, szConfigFilename);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    app_tracef("INFO: Configuration file (JSON format) [%s] (%u bytes)", szConfigFilename, strlen(szJsonConfig));

    rc = __ParseJsonConfig(szJsonConfig, pIBRand);
    if (!rc)
    {
        app_tracef("ERROR: Error %d parsing JSON config\n", rc);
        if (szJsonConfig) free(szJsonConfig);
        return rc;
    }
    if (szJsonConfig) free(szJsonConfig);

    return 0;
}
#endif // USE_CONFIG

static void PrintConfig(tIB_INSTANCEDATA *pIBRand)
{
    app_tracef("szStorageType         =[%s]" , pIBRand->szStorageType         ); // char          szStorageType            [16]   // "FILE";
    app_tracef("szStorageDataFormat   =[%s]" , pIBRand->szStorageDataFormat   ); // char          szStorageDataFormat      [16]   // RAW, BASE64, HEX
    app_tracef("szStorageFilename     =[%s]" , pIBRand->szStorageFilename     ); // char          szStorageFilename        [128]  // "/var/lib/ibrand/ibrand_data.bin";
    app_tracef("szStorageLockfilePath =[%s]" , pIBRand->szStorageLockfilePath ); // char          szStorageLockfilePath    [128]  // "/tmp";
    app_tracef("storageHighWaterMark  =[%ld]", pIBRand->storageHighWaterMark  ); // long          storageHighWaterMark            // 1038336; // 1MB
    app_tracef("storageLowWaterMark   =[%ld]", pIBRand->storageLowWaterMark   ); // long          storageLowWaterMark             // 102400; // 100KB
    app_tracef("fVerbose              =[%u]" , pIBRand->fVerbose              ); // unsigned char fVerbose                        // bit 0=general, bit1=auth, bit2=data, bit3=curl:
}
