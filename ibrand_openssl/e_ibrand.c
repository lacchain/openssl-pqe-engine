// Copyright 2018 Thomás Inskip. All rights reserved.
// https://github.com/tinskip/infnoise-openssl-engine
//
// Implementation of OpenSSL RAND engine which uses the infnoise TRNG to
// generate true random numbers: https://github.com/waywardgeek/infnoise
//
// 23/06/2020: Changes added to support IronBridge RNG API
//

#include <libibrand.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "../ibrand_common/my_utilslib.h"

//#define USE_RINGBUFFER // Can cause problems with genrsa >= 2048

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

static const int ENGINE_STATUS_OK = 1;
static const int ENGINE_STATUS_NG = 0;

static const int localDebugTracing = true;

///////////////////
// Configuration
///////////////////

////////////////////////////////
// Ring buffer implementation
////////////////////////////////

#ifdef USE_RINGBUFFER

#define RING_BUFFER_SIZE (2u * BUFLEN) // So that we do not waste RNG bytes.
#define RING_BUFFER_REPLENISH_SIZE (BUFLEN)

typedef struct
{
  uint8_t buffer[RING_BUFFER_SIZE];
  uint8_t *r_ptr;
  uint8_t *w_ptr;
} RingBuffer;

static void RingBufferInit(RingBuffer *buffer)
{
  memset(buffer->buffer, 0, sizeof(buffer->buffer));
  buffer->r_ptr = buffer->buffer;
  buffer->w_ptr = buffer->buffer;
}

static size_t RingBufferRead(RingBuffer *buffer, size_t num_bytes, uint8_t *output)
{
  size_t total_bytes_read = 0;

  if (buffer->r_ptr > buffer->w_ptr)
  {
    size_t bytes_in_front = RING_BUFFER_SIZE - (buffer->r_ptr - buffer->buffer);
    size_t bytes_read = MIN(num_bytes, bytes_in_front);
    memcpy(output, buffer->r_ptr, bytes_read);
    if (bytes_read < bytes_in_front)
    {
      buffer->r_ptr += bytes_read;
      return bytes_read;
    }
    buffer->r_ptr = buffer->buffer;
    total_bytes_read += bytes_read;
    num_bytes -= bytes_read;
  }

  size_t bytes_read = MIN(num_bytes, (size_t)(buffer->w_ptr - buffer->r_ptr));
  memcpy(output, buffer->r_ptr, bytes_read);
  buffer->r_ptr += bytes_read;
  if ((buffer->r_ptr - buffer->buffer) == sizeof(buffer->buffer))
  {
    buffer->r_ptr = buffer->buffer;
  }
  total_bytes_read += bytes_read;

  return total_bytes_read;
}

static size_t RingBufferWrite(RingBuffer *buffer, size_t num_bytes, const uint8_t *input)
{
  size_t total_bytes_written = 0;

  if (buffer->w_ptr > buffer->r_ptr)
  {
    size_t free_bytes_in_front = RING_BUFFER_SIZE - (buffer->w_ptr - buffer->buffer);
    size_t bytes_write = MIN(num_bytes, free_bytes_in_front);
    memcpy(buffer->w_ptr, input, bytes_write);
    if (bytes_write < num_bytes)
    {
      buffer->w_ptr += bytes_write;
      return bytes_write;
    }
    buffer->w_ptr = buffer->buffer;
    total_bytes_written += bytes_write;
    num_bytes -= bytes_write;
  }

  size_t bytes_write = MIN(num_bytes, (size_t)(RING_BUFFER_SIZE - (buffer->w_ptr - buffer->r_ptr)));
  memcpy(buffer->w_ptr, input, bytes_write);
  buffer->w_ptr += bytes_write;
  if ((buffer->w_ptr - buffer->buffer) == sizeof(buffer->buffer))
  {
    buffer->w_ptr = buffer->buffer;
  }
  total_bytes_written += bytes_write;

  return total_bytes_written;
}
#endif // USE_RINGBUFFER

///////////////////////////
// Engine implementation
///////////////////////////

typedef struct tagENGINESTATE
{
  struct ibrand_context trng_context;
#ifdef USE_RINGBUFFER
  RingBuffer ring_buffer;
#endif
  int status;
} tENGINESTATE;

static int IBRandEngineStateInit(tENGINESTATE *pEngineState)
{
  app_trace_set_destination(false, false, true); // (toConsole, toLogFile; toSyslog)
  app_trace_openlog(NULL, LOG_PID, LOG_USER );

  memset(pEngineState, 0, sizeof(*pEngineState));
#ifdef USE_RINGBUFFER
  RingBufferInit(&pEngineState->ring_buffer);
#endif
  pEngineState->status = IBRand_init(&pEngineState->trng_context);
  if (!pEngineState->status)
  {
    app_tracef("ERROR: IBRand_init initialization error: %s", pEngineState->trng_context.message ? pEngineState->trng_context.message : "unknown");
  }

  return pEngineState->status;
}

#ifdef USE_RINGBUFFER
static tENGINESTATE engine_state = {{NULL, {0}, 0, 0},{{0},NULL,NULL},0};
#else
static tENGINESTATE engine_state = {{NULL, {0}, 0, 0},0};
#endif


static int GetRngMaterial(unsigned char *buf, int num)
{
  unsigned long bytesStillRequired = num;

  UNUSED_VAR(localDebugTracing);

  unsigned char *w_ptr = buf;
  while ((bytesStillRequired > 0) && (engine_state.status == ENGINE_STATUS_OK))
  {
#ifdef USE_RINGBUFFER
    size_t bytes_read = RingBufferRead(&engine_state.ring_buffer, bytesStillRequired, w_ptr);
    w_ptr += bytes_read;
    bytesStillRequired -= bytes_read;
    //if (localDebugTracing) app_tracef("DEBUG: RingBufferRead Supplied=%lu. ShortFall=%u", bytes_read, bytesStillRequired);

    // Has the request been satisfied, or do we still have a requirement?
    if (bytesStillRequired > 0)
    {
      // Need more RNG bytes - restock ring buffer, and then try again
      uint8_t rand_buffer[RING_BUFFER_REPLENISH_SIZE];

      // Due to the frequency of the bind call, we were wasting a lot of material each time the ring buffer was being initialised.
      // Changed to request only the number of bytes we need, iso always retrieving RING_BUFFER_REPLENISH_SIZE.
      // (If this proves effective, it may make the RingBuffer redundant).
      unsigned long shMemRequestBytes = MIN(bytesStillRequired, (int)RING_BUFFER_REPLENISH_SIZE); // was RING_BUFFER_REPLENISH_SIZE

      //if (localDebugTracing) app_tracef("DEBUG: Replenish RingBuffer from shmem(%d)", shMemRequestBytes);
      size_t rand_bytes = IBRand_readData(&engine_state.trng_context, rand_buffer, shMemRequestBytes);
      if (engine_state.trng_context.errorCode)
      {
        app_tracef("ERROR: IBRand_readData failed: errorCode=%d, msg=%s", engine_state.trng_context.errorCode, engine_state.trng_context.message ? engine_state.trng_context.message : "unknown");
        engine_state.status = ENGINE_STATUS_NG;
        engine_state.trng_context.errorCode = 0;
        break;
      }
      size_t bytes_written = RingBufferWrite(&engine_state.ring_buffer, rand_bytes, rand_buffer);
      if (bytes_written != rand_bytes)
      {
        app_tracef("ERROR: Invalid ibrand engine buffer state");
        engine_state.status = ENGINE_STATUS_NG;
        break;
      }
      //if (localDebugTracing) app_tracef("DEBUG: RingBuffer replenished with %lu bytes. Try again...", (unsigned long)bytes_written);
    }
#else // USE_RINGBUFFER
      unsigned long shMemRequestBytes = bytesStillRequired;
      size_t rand_bytes = IBRand_readData(&engine_state.trng_context, w_ptr, shMemRequestBytes);
      if (engine_state.trng_context.errorCode)
      {
        app_tracef("ERROR: IBRand_readData failed: errorCode=%d, msg=%s", engine_state.trng_context.errorCode, engine_state.trng_context.message ? engine_state.trng_context.message : "unknown");
        engine_state.status = ENGINE_STATUS_NG;
        engine_state.trng_context.errorCode = 0;
        break;
      }
      w_ptr += rand_bytes;
      bytesStillRequired -= rand_bytes;
#endif // USE_RINGBUFFER
  }
  //if (localDebugTracing) app_tracef("DEBUG: Inbound openssl rand (requested:%d, supplied:%d) Done", requestBytes, requestBytes-bytesStillRequired);

  return engine_state.status;
}

static int cb_GetRngMaterial(unsigned char *buf, int num)
{
  if (localDebugTracing) app_tracef("INFO: cb_GetRngMaterial(%d)", num);
  return GetRngMaterial(buf, num);
}

static int cb_GetPseudoRandMaterial(unsigned char *buf, int num)
{
  if (localDebugTracing) app_tracef("INFO: cb_GetPseudoRandMaterial(%d)", num);
  return GetRngMaterial(buf, num);
}


static int cb_Status(void)
{
    return engine_state.status;
}

static void cb_Cleanup(void)
{
  if (localDebugTracing) app_tracef("INFO: cb_Cleanup() [waterlevel=%d]", engine_state.trng_context.recentWaterLevel);
}

int ibrand_bind(ENGINE *pEngine, const char *pID)
{
  static const char ENGINE_ID[]   = "ibrand";
  static const char ENGINE_NAME[] = "CQC IronBridge SRNG rand engine";

  static RAND_METHOD engineCallbackFunctions = {NULL,                      // int (*seed) (const void *buf, int num);
                                                &cb_GetRngMaterial,        // int (*bytes) (unsigned char *buf, int num);
                                                &cb_Cleanup,               // void (*cleanup) (void);
                                                NULL,                      // int (*add) (const void *buf, int num, double randomness);
                                                &cb_GetPseudoRandMaterial, // int (*pseudorand) (unsigned char *buf, int num);   -- No 'pseudo'.
                                                &cb_Status};               // int (*status) (void);
  (void)pID; // Unused variable

  if (localDebugTracing) app_tracef("INFO: ibrand_bind()");

  if (ENGINE_set_id  (pEngine, ENGINE_ID               ) != ENGINE_STATUS_OK ||
      ENGINE_set_name(pEngine, ENGINE_NAME             ) != ENGINE_STATUS_OK ||
      ENGINE_set_RAND(pEngine, &engineCallbackFunctions) != ENGINE_STATUS_OK)
  {
    app_tracef("ERROR: ibrand_lib: Binding failed");
    return ENGINE_STATUS_NG;
  }

  if (IBRandEngineStateInit(&engine_state) != ENGINE_STATUS_OK)
  {
    app_tracef("ERROR: IBRandEngineStateInit failed");
    return ENGINE_STATUS_NG;
  }

  if (localDebugTracing) app_tracef("INFO: ibrand_bind() OK");
  return ENGINE_STATUS_OK;
}

IMPLEMENT_DYNAMIC_BIND_FN(ibrand_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
