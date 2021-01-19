
// JGilmore (07/12/2020 12:26)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h> // To seed the rand() function
#include <openssl/engine.h>
#include <openssl/evp.h>

#include "../ibrand_common/my_utilslib.h"

static const int ENGINE_STATUS_OK = 1;
static const int ENGINE_STATUS_NG = 0;

static const int localDebugTracing_Debug = false;
static const int localDebugTracing_Info = false;
static const int printTotalsToStdOut = false;

typedef struct tagENGINESTATE
{
    int status;
} tENGINESTATE;

static tENGINESTATE engine_state = {ENGINE_STATUS_NG};

static long int g_InstanceTotalBytesRequested = 0;


///////////////////////////
// Engine implementation
///////////////////////////


static int ibinit_EngineStateInit(tENGINESTATE *pEngineState)
{
    app_trace_set_destination(false, false, true); // (toConsole, toLogFile; toSyslog)
    app_trace_openlog(NULL, LOG_PID, LOG_USER );

    memset(pEngineState, 0, sizeof(*pEngineState));
    srand(time(NULL));   // Initialization, should only be called once.
    pEngineState->status = ENGINE_STATUS_OK;

    return pEngineState->status;
}

static int ibinit_GetRngMaterial(unsigned char *buf, int requestedBytes)
{
    unsigned long bytesStillRequired = requestedBytes;
    unsigned char *w_ptr = buf;
    unsigned int r;

    UNUSED_VAR(localDebugTracing_Debug);
    UNUSED_VAR(localDebugTracing_Info);
    UNUSED_VAR(printTotalsToStdOut);

    while ((bytesStillRequired > 0) && (engine_state.status == ENGINE_STATUS_OK))
    {
        r = (unsigned int)rand(); // Returns a pseudo-random integer between 0 and RAND_MAX.
        if (bytesStillRequired >= sizeof(unsigned int))
        {
            // Consume all of the received bytes
            *((unsigned int *)w_ptr) = r;
            w_ptr += sizeof(unsigned int);
            bytesStillRequired -= sizeof(unsigned int);
        }
        else
        {
            // Consume just 1 of the received bytes
            *w_ptr = r & 0xFF;
            w_ptr += 1;
            bytesStillRequired -= 1;
        }
    }
    g_InstanceTotalBytesRequested += requestedBytes;
    if (localDebugTracing_Debug)
    {
        app_tracef("DEBUG: (IBINIT_ENGINE) GetRngMaterial (requested:%d, supplied:%ld, InstanceTotal=%ld) Done\n", requestedBytes, requestedBytes-bytesStillRequired, g_InstanceTotalBytesRequested);
    }
    //if (printTotalsToStdOut)
    //{
    //   fprintf(stderr, "*** INFO: (IBINIT_ENGINE) GetRngMaterial (requested:%d, supplied:%ld, InstanceTotal=%ld) Done\n", requestedBytes, requestedBytes-bytesStillRequired, g_InstanceTotalBytesRequested);
    //}
    return engine_state.status;
}

static int cb_GetRngMaterial(unsigned char *buf, int num)
{
    static int depth = 0;
    int rc;

    depth++;
    if (localDebugTracing_Info)
    {
        app_tracef("INFO: (IBINIT_ENGINE) cb_GetRngMaterial(%d)", num);
    }
    rc = ibinit_GetRngMaterial(buf, num);
    depth--;
    return rc;
}

static int cb_GetPseudoRandMaterial(unsigned char *buf, int num)
{
    if (localDebugTracing_Info)
    {
        app_tracef("INFO: (IBINIT_ENGINE) cb_GetPseudoRandMaterial(%d)", num);
    }
    return ibinit_GetRngMaterial(buf, num);
}

static int cb_Status(void)
{
    return engine_state.status;
}

static void cb_Cleanup(void)
{
    if (localDebugTracing_Info)
    {
        app_tracef("INFO: (IBINIT_ENGINE) cb_Cleanup() (InstanceTotal=%ld)", g_InstanceTotalBytesRequested);
    }
    if (printTotalsToStdOut)
    {
        fprintf(stderr, "*** INFO: (IBINIT_ENGINE) cb_Cleanup() (InstanceTotal=%ld)\n", g_InstanceTotalBytesRequested);
    }
}

int ibinit_bind(ENGINE *pEngine, const char *pID)
{
    static const char ENGINE_ID[]   = "ibinit";
    static const char ENGINE_NAME[] = "CQC IronBridge IBInit Initialisation engine";

    static RAND_METHOD engineCallbackFunctions = {NULL,                      // int (*seed) (const void *buf, int num);
                                                  &cb_GetRngMaterial,        // int (*bytes) (unsigned char *buf, int num);
                                                  &cb_Cleanup,               // void (*cleanup) (void);
                                                  NULL,                      // int (*add) (const void *buf, int num, double randomness);
                                                  &cb_GetPseudoRandMaterial, // int (*pseudorand) (unsigned char *buf, int num);   -- No 'pseudo'.
                                                  &cb_Status};               // int (*status) (void);
    (void)pID; // Unused variable

    if (localDebugTracing_Debug)
    {
        app_tracef("DEBUG: (IBINIT_ENGINE) ibinit_bind()");
    }

    if (ENGINE_set_id  (pEngine, ENGINE_ID               ) != ENGINE_STATUS_OK ||
        ENGINE_set_name(pEngine, ENGINE_NAME             ) != ENGINE_STATUS_OK ||
        ENGINE_set_RAND(pEngine, &engineCallbackFunctions) != ENGINE_STATUS_OK)
    {
      app_tracef("ERROR: (IBINIT_ENGINE) ibinit_bind: Binding failed");
      return ENGINE_STATUS_NG;
    }

    if (ibinit_EngineStateInit(&engine_state) != ENGINE_STATUS_OK)
    {
      app_tracef("ERROR: (IBINIT_ENGINE) ibinit_EngineStateInit failed");
      return ENGINE_STATUS_NG;
    }

    g_InstanceTotalBytesRequested = 0;
    if (localDebugTracing_Debug)
    {
        app_tracef("DEBUG: (IBINIT_ENGINE) ibinit_bind() OK");
    }
    return ENGINE_STATUS_OK;
}

IMPLEMENT_DYNAMIC_BIND_FN(ibinit_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
