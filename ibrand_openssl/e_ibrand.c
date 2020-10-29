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

#include "my_utilslib.h"

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

///////////////////////////
// Engine implementation
///////////////////////////

typedef struct tagENGINESTATE
{
  struct ibrand_context trng_context;
  RingBuffer ring_buffer;
  int status;
} tENGINESTATE;

static int IBRandEngineStateInit(tENGINESTATE *engine_state)
{
  app_trace_set_destination(false, false, true); // (toConsole, toLogFile; toSyslog)
  app_trace_openlog(NULL, LOG_PID, LOG_USER );

  memset(engine_state, 0, sizeof(*engine_state));
  RingBufferInit(&engine_state->ring_buffer);
  engine_state->status = initIBRand(&engine_state->trng_context);
  if (!engine_state->status)
  {
    app_tracef("ERROR: initIBRand initialization error: %s", engine_state->trng_context.message ? engine_state->trng_context.message : "unknown");
  }

  return engine_state->status;
}

static tENGINESTATE engine_state = {0};


static int Bytes(unsigned char *buf, int num)
{

  UNUSED_VAR(localDebugTracing);

  unsigned char *w_ptr = buf;
  while ((num > 0) && (engine_state.status == ENGINE_STATUS_OK))
  {
    size_t bytes_read = RingBufferRead(&engine_state.ring_buffer, num, w_ptr);
    w_ptr += bytes_read;
    num -= bytes_read;
    //if (localDebugTracing) app_tracef("DEBUG: RingBufferRead Supplied=%lu. ShortFall=%u", bytes_read, bytesStillRequired);

    if (num > 0)
    {
      // Need more RNG bytes - restock ring buffer, and then try again
      uint8_t rand_buffer[RING_BUFFER_REPLENISH_SIZE];
      //if (localDebugTracing) app_tracef("DEBUG: Replenish RingBuffer from shmem(%d)", shMemRequestBytes);
      size_t rand_bytes = readData(&engine_state.trng_context, rand_buffer, RING_BUFFER_REPLENISH_SIZE);
      if (engine_state.trng_context.errorCode)
      {
        app_tracef("ERROR: readData failed: errorCode=%d, msg=%s", engine_state.trng_context.errorCode, engine_state.trng_context.message ? engine_state.trng_context.message : "unknown");
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
  }
  //if (localDebugTracing) app_tracef("DEBUG: Inbound openssl rand (requested:%d, supplied:%d) Done", requestBytes, requestBytes-bytesStillRequired);

  return engine_state.status;
}

static int Status(void)
{
    return engine_state.status;
}

int ibrand_bind(ENGINE *engine, const char *id)
{
  static const char kEngineId[] = "ibrand";
  static const char kEngineName[] = "IronBridge SRNG rand engine";

  static RAND_METHOD rand_method = {NULL,   &Bytes, NULL, NULL,
                                    &Bytes, // No 'pseudo'.
                                    &Status};

  (void)id; // Unused variable

  if (localDebugTracing) app_tracef("INFO: ibrand_bind()");

  if (ENGINE_set_id(engine, kEngineId) != kEngineOk ||
      ENGINE_set_name(engine, kEngineName) != kEngineOk ||
      ENGINE_set_RAND(engine, &rand_method) != kEngineOk)
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
