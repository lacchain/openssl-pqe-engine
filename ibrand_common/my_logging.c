
///////////////////////////////////////////////////////////////////////////////
// Some Useful Logging Utilities
// Copyright (c) 1998-2020 Jonathan Gilmore. All rights reserved.
// Original: J. Gilmore, Fri 02-Oct-1998, 16:11:57
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>

#include "../ibrand_common/my_utils.h"
#include "../ibrand_common/my_logging.h"

//#define MK_WIN_EMUL
#define OUTPUT_TO_CONSOLE_ENABLED
#define OUTPUT_TO_LOGFILE_ENABLED
#define OUTPUT_TO_SYSLOG_ENABLED
#define ALSO_LOG_INTERNAL_ERRORS

#ifdef OUTPUT_TO_SYSLOG_ENABLED
#include <syslog.h>
#endif

#ifndef _MAX_PATH
#define _MAX_PATH 128
#endif



typedef struct tagAPPTRACECONFIG
{
    char logFilePath[_MAX_PATH];
    char logFilename[_MAX_PATH];
    bool logToConsole;
    bool logToLogfile;
    bool logToSyslog;
} tAPPTRACECONFIG;

static tAPPTRACECONFIG _gAppTraceConfig = {"/var/lib/unknown", "unknown_component.log", false, false, true};


///////////////////////////////////////////////////////////////////////////////
// Logging Functions
///////////////////////////////////////////////////////////////////////////////

static void app_timer_delay (int ms)
{
    // TODO app_timer_delay
    UNUSED_PARAM(ms);
}

static char *FormatCharHex ( char *szTarget, unsigned char ch )
////////////////////////////////////////////////////////////
// Jonnie, Fri 02-Oct-1998, 16:11:57
////////////////////////////////////////////////////////////
{
   sprintf(szTarget+strlen(szTarget),"<0x%2.2X>",ch);
   return szTarget;
}

static char *FormatCharSimpleHex ( char *szTarget, unsigned char ch )
////////////////////////////////////////////////////////////
// Jonnie, Fri 02-Oct-1998, 16:11:57
////////////////////////////////////////////////////////////
{
    sprintf(szTarget+strlen(szTarget),"%2.2X",ch);
    return szTarget;
}

static char *FormatCharDisplayable ( char *szTarget, unsigned char ch )
////////////////////////////////////////////////////////////
// Jonnie, Fri 02-Oct-1998, 16:11:57
////////////////////////////////////////////////////////////
{
   if      (ch=='\r')
      sprintf(szTarget+strlen(szTarget),"<CR>");
   else if (ch=='\n')
      sprintf(szTarget+strlen(szTarget),"<LF>");
   else if ((ch<' ') || (ch>'~'))
      FormatCharHex ( szTarget, ch );
   else
      sprintf(szTarget+strlen(szTarget),"%c", ch);
   return szTarget;
}

char *FormatData ( char *szTarget, const char *szTitle, const unsigned char *pData, int cbData, tOUTPUTFORMAT fOutputFormat )
////////////////////////////////////////////////////////////
// Jonnie, Thu 01-Oct-1998, 11:20:50
// Minimum length of szTarget is...
//  max 6 bytes per character eg "<0x12>"
//  plus space for ":==>" and "<=="
//  plus space for trailing NULL
//  eg malloc_size = (cbData*6)+(pHeader?strlen(pHeader)+4+3+1:0);
////////////////////////////////////////////////////////////
{
   int i;

#ifdef MK_WIN_EMUL
   // Set this task temporarily to very high priority
   // so that the debug output can be completed without
   // interruption from debug output from any other threads.
   // This is particularly useful in debugging the pipe
   // functionality in the browser.
   int PrevPriority;
   HANDLE hThread;
   hThread = GetCurrentThread();
   PrevPriority = GetThreadPriority(hThread);
   SetThreadPriority(hThread,THREAD_PRIORITY_TIME_CRITICAL);
#endif

   if (!szTarget)
   {
     return NULL;
   }

   if (!pData)
   {
      pData = (unsigned char *)"[NULLPTR]";
      cbData = (int)strlen((const char *)pData);
   }

   if (cbData == -1)
      cbData = (int)strlen((char *)pData);

   szTarget[0] = 0;
   if (szTitle)
      sprintf(szTarget+strlen(szTarget),"%s (len=%d) ==>", szTitle, cbData);
   for (i=0;i<cbData;i++)
   {
      switch (fOutputFormat)
      {
         default:
         case NONDISPLAYABLE_IN_PRETTY_HEX:
            FormatCharDisplayable ( szTarget, pData[i] );
            break;
         case ALL_IN_PRETTY_HEX:
            FormatCharHex ( szTarget, pData[i] );
            break;
         case ALL_IN_BASIC_HEX:
            FormatCharSimpleHex ( szTarget, pData[i] );
            break;
      }
   }
   if (szTitle)
     sprintf(szTarget+strlen(szTarget),"<==");
#ifdef MK_WIN_EMUL
   SetThreadPriority(hThread,PrevPriority);
#endif
   return szTarget;
}

void app_trace_hex(const char *pHeader, const unsigned char *pData, unsigned int cbData)
{
  char *pTemp;
  size_t malloc_size;

  malloc_size = (cbData*6);           // Space for Max 6 hex chars per byte eg "<0xEF>"
  if (pHeader)
  {
      malloc_size += strlen(pHeader); // Space for "%s"
      malloc_size += 18;              // Space for " (len=4294967295) "
      malloc_size += 6;               // Space for "==>" and "<=="
  }
  malloc_size += 1;                   // Space for trailing NULL

  pTemp = (char *)malloc(malloc_size);
  if (pTemp)
  {
    app_traceln(FormatData(pTemp, pHeader, (unsigned char *)pData, cbData, NONDISPLAYABLE_IN_PRETTY_HEX));
    app_timer_delay(10);
    free(pTemp);
  }
  else
  {
    char tempStr[20];
#ifdef ALSO_LOG_INTERNAL_ERRORS
    app_trace("ERROR: Cannot display data do due malloc failure: ==>\"");
#else
    app_trace("Data ==>\"");
#endif
    app_trace(pHeader);
    app_trace("\", ");
    sprintf(tempStr, "%u bytes", cbData);
    app_trace(tempStr);
    app_traceln("<==");
    app_timer_delay(10);
  }
}

void app_trace_hexall(const char *pHeader, const unsigned char *pData, unsigned int cbData)
{
  char *pTemp;
  size_t malloc_size;

  malloc_size = (cbData*2);           // Space for 2 hex chars per byte eg "EF"
  if (pHeader)
  {
      malloc_size += strlen(pHeader); // Space for "%s"
      malloc_size += 18;              // Space for " (len=4294967295) "
      malloc_size += 6;               // Space for "==>" and "<=="
  }
  malloc_size += 1;                   // Space for trailing NULL

  pTemp = (char *)malloc(malloc_size);
  if (pTemp)
  {
    app_traceln(FormatData(pTemp, pHeader, (unsigned char *)pData, cbData, ALL_IN_BASIC_HEX)); // NB FALSE <=========== ALL chars in hex
    app_timer_delay(10);
    free(pTemp);
  }
  else
  {
    char tempStr[20];
#ifdef ALSO_LOG_INTERNAL_ERRORS
    app_trace("ERROR: Cannot display data do due malloc failure: ==>\"");
#else
    app_trace("Data ==>\"");
#endif
    app_trace(pHeader);
    app_trace("\", ");
    sprintf(tempStr, "%u bytes", cbData);
    app_trace(tempStr);
    app_traceln("<==");
    app_timer_delay(10);
  }
}

#ifdef OUTPUT_TO_LOGFILE_ENABLED
#ifdef INCLUDE_WINDOWS_TYPE_FUNCTIONS
static const char * WinGetEnv(const char * name)
{
    const DWORD buffSize = 65535;
    static char buffer[buffSize];
    if (GetEnvironmentVariableA(name, buffer, buffSize))
    {
        return buffer;
    }
    else
    {
        return 0;
    }
}
#endif // INCLUDE_WINDOWS_TYPE_FUNCTIONS
#endif // OUTPUT_TO_LOGFILE_ENABLED

void app_trace_openlog(const char *ident, int logopt, int facility)
{
#ifdef OUTPUT_TO_SYSLOG_ENABLED
   // void openlog(const char *ident, int logopt, int facility);
   // e.g. logopt  : LOG_PID | LOG_CONS | LOG_PERROR
   //      facility: LOG_DAEMON or LOG_USER
   openlog(ident, logopt, facility);
#endif
}

void app_trace_closelog(void)
{
#ifdef OUTPUT_TO_SYSLOG_ENABLED
   closelog();
#endif
}

static void appendToLogfile(const char *szString, bool emitCrLf)
{
#ifdef OUTPUT_TO_SYSLOG_ENABLED
  if (_gAppTraceConfig.logToSyslog)
  {
    // void syslog(int priority, const char *message, ... );
    syslog(LOG_ERR, "%s%s", szString, emitCrLf?"\n":"");
    // LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO and LOG_DEBUG
  }
#endif

#ifdef OUTPUT_TO_LOGFILE_ENABLED
    if (_gAppTraceConfig.logToLogfile)
    {
        FILE *fLogfile;
        const char *pszLogFilename;
        static int bInitialised = FALSE;

        // We'll open and close every time for now, to aid debugging...
        pszLogFilename = app_trace_get_logfilename(_gAppTraceConfig.logFilename);
        if (!bInitialised)
        {
            fprintf(stderr, "Appending to Logfile: \"%s\"\n",pszLogFilename);
        }
        fLogfile = fopen(pszLogFilename, "at");
        if (!fLogfile)
        {
            fLogfile = fopen(pszLogFilename, "wt");
        }
        if (!fLogfile)
        {
            if (errno == EACCES) // 13
                fprintf(stderr, "FATAL: Error opening Logfile: \"%s\". errno=EACCES(13,Permission denied). Terminating.\n",pszLogFilename);
            else
                fprintf(stderr, "FATAL: Error opening Logfile: \"%s\". errno=%d. Terminating.\n",pszLogFilename, errno);
            return;
        }
        bInitialised = TRUE;

        fwrite(szString,1,strlen(szString),fLogfile);
        if (emitCrLf)
        {
            fwrite(EOL,1,strlen(EOL),fLogfile);
        }
        fclose(fLogfile);
    }
#endif // OUTPUT_TO_LOGFILE_ENABLED
}

void app_trace_set_destination(bool toConsole, bool toLogfile, bool toSyslog)
{
#ifdef OUTPUT_TO_CONSOLE_ENABLED
    _gAppTraceConfig.logToConsole = toConsole;
#endif
#ifdef OUTPUT_TO_LOGFILE_ENABLED
    _gAppTraceConfig.logToLogfile = toLogfile;
#endif
#ifdef OUTPUT_TO_SYSLOG_ENABLED
    _gAppTraceConfig.logToSyslog = toSyslog;
#endif
}

void app_trace_set_logfilename(const char *szPath, const char *szFilename)
{
#ifdef OUTPUT_TO_LOGFILE_ENABLED
    strcpy(_gAppTraceConfig.logFilePath, szPath);     // e.g. "/var/lib/<projectname>";
    strcpy(_gAppTraceConfig.logFilename, szFilename); // e.g. "<projectname>_<component>.log"};
#endif
}

const char *app_trace_get_logfilename(const char *szFilename)
{
    static char szLogFilename[_MAX_PATH];
#ifdef INCLUDE_WINDOWS_TYPE_FUNCTIONS
    const char *szTempPath = WinGetEnv("TEMP");
    strcpy(szLogFilename, szTempPath?szTempPath:"C:\\");
#else
    strcpy(szLogFilename, _gAppTraceConfig.logFilePath);
#endif
    if (szLogFilename[strlen(szLogFilename)] != PATHSEPARATOR)
        strcat(szLogFilename, PATHSEPARATORSTR);
    strcat(szLogFilename, szFilename);
    return szLogFilename;
}

#ifdef OUTPUT_TO_CONSOLE_ENABLED
static void OutputDebugStringA(const char *szString)
{
    int n;
    if (_gAppTraceConfig.logToConsole)
    {
        //printf(szString);
        n = write(STDERR_FILENO, szString, strlen(szString));
    }
    UNUSED_PARAM(n);
}
#endif // OUTPUT_TO_CONSOLE_ENABLED

static void __app_trace(const char *szString, bool emitCrLf)
{
    //TRACE ("msg=%s, int=%d\n", (LPCTSTR)sMsg, i);
    //OutputDebugString (LPCTSTR szMessage)
    //app_traceln(szMessage);

#ifdef OUTPUT_TO_CONSOLE_ENABLED
    OutputDebugStringA(szString);
    if (emitCrLf)
        OutputDebugStringA(EOL);
#endif // OUTPUT_TO_CONSOLE_ENABLED

    // Append this to our log file or syslog, if enabled
    appendToLogfile(szString, emitCrLf);
}

void app_traceln(const char *szString)
{
    __app_trace(szString, true);
}

void app_trace(const char *szString)
{
    __app_trace(szString, false);
}

int app_tracef(const char *formatStr, ...)
{
#define SPRINTF_TRACE_BUFSIZE (32*1024)
    va_list va;
    char *pBuf;
    int rc;

    pBuf = (char *)malloc(SPRINTF_TRACE_BUFSIZE);
    if (!pBuf)
    {
        return -1;
    }
    va_start(va, formatStr);
    rc = vsnprintf(pBuf, SPRINTF_TRACE_BUFSIZE, formatStr, va);
    if (rc == -1 || rc >= SPRINTF_TRACE_BUFSIZE)
    {
        free(pBuf);
        return -1;
    }
    app_traceln(pBuf);
    va_end(va);
    free(pBuf);
    return rc;
}

///////////////////////////////////////////////////////////////////////////////
// GetToken Functions
///////////////////////////////////////////////////////////////////////////////

int my_getToken(const char *pSrcData, char *pDstField, int nFieldNum, int nDstFieldMaxLen)
///////////////////////////////////////////////////////////////////////////////
// Name:    GetToken
// Description: This function will get the specified field in a string.
// Entry: char *pSrcData      - Ptr to source string containing multiple fields
//        char *pDstField     - Ptr to returned field
//        int nfieldNum       - Field to get, origin 0
//        int nDstFieldMaxLen - Max bytes pDstField can handle
///////////////////////////////////////////////////////////////////////////////
{
  int i = 0;
  int nField = 0;
  int j = 0;

  // Validate params
  if ((pSrcData == NULL) || (pDstField == NULL) || (nDstFieldMaxLen <= 0))
    return FALSE;

  // Go to the beginning of the selected field
  for(;;)
  {
    if (nField >= nFieldNum)
      break;
    if (pSrcData[i] == 0)
      break;
    if (pSrcData[i] == ',')
      nField++;
    i++;
  }

  // Variable i now is the index of the first character of the next token
  // eg if pSrcData = "2,1  ]"
  // then, with nFieldNum=0, i will now be 0
  //       with nFieldNum=1, i will now be 2

  // Copy field from pSrcData to Field
  for (;;)
  {
    if (pSrcData[i] == ',')
      break;
    if (pSrcData[i] == '*')
      break;
    if (pSrcData[i] == 0)
      break;

    pDstField[j] = pSrcData[i];
    j++;

    i++;
    // Check if field is too big to fit on passed parameter. If it is,
    // crop returned field to its max length.
    if (j >= nDstFieldMaxLen)
    {
      j = nDstFieldMaxLen - 1;
      break;
    }
  }
  pDstField[j] = 0;
  if (j<=0)
  {
#ifdef ALSO_LOG_INTERNAL_ERRORS
    app_traceln("TRACE: GetToken found token with zero length");
    app_timer_delay(10);
#endif
    return FALSE;
  }

  my_trimLeading(pDstField,(char *)" [");
  my_trimTrailing(pDstField,(char *)" ]");

  app_trace_hex ("TRACE: GetToken pSrcData=", (unsigned char *)pSrcData, strlen(pSrcData));
  char buf[20];
  my_itoa (nFieldNum, buf, 10);
  app_trace_hex ("TRACE: GetToken nFieldNum=", (unsigned char *)buf, strlen(buf));
  app_trace_hex ("TRACE: GetToken pDstField=", (unsigned char *)pDstField, strlen(pDstField));
  app_timer_delay(10);

  return TRUE;
}

void my_dumpToFile(const char *szFilename, const unsigned char *p, size_t n)
{
    app_tracef("Dumping %d bytes to %s", n, szFilename);
    FILE *f = fopen(szFilename, "wb");
    if (!f)
    {
        app_tracef("ERROR: DumpToFile - open failed");
        return;
    }
    size_t bytesWritten = fwrite(p,1,n,f);
    if (bytesWritten != n)
    {
       app_tracef("ERROR: DumpToFile - write failed");
       fclose(f);
       return;
    }
    fclose(f);
}

const char *HttpResponseCodeCategory(int httpResponseCode)
{
    switch(httpResponseCode/100)
    {
        case 100: return "[Informational 1xx]";
        case 200: return "[Successful 2xx]";
        case 300: return "[Redirection 3xx]";
        case 400: return "[Client Error 4xx]";
        case 500: return "[Server Error 5xx]";
        default:
            break;
    }
    return "[Unknown]";
}

const char *HttpResponseCodeDescription(int httpResponseCode)
{
    switch(httpResponseCode)
    {
        // [Informational 1xx]
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        // [Successful 2xx]
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        // [Redirection 3xx]
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "(Unused)";
        case 307: return "Temporary Redirect";
        // [Client Error 4xx]
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
        // [Server Error 5xx]
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
    }
    return "Unknown";
}
