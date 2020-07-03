
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


#include "my_utils.h"
#include "my_logging.h"

//#define MK_WIN_EMUL
//#define OUTPUT_TO_CONSOLE_ENABLED
#define OUTPUT_TO_LOGFILE_ENABLED
#define OUTPUT_TO_SYSLOG_ENABLED
#define ALSO_LOG_INTERNAL_ERRORS


#ifndef OUTPUT_TO_SYSLOG_ENABLED
static char DEFAULTLOGFILEPATH[_MAX_PATH] = {"/var/lib/unknown"};
static char DEFAULTLOGFILENAME[_MAX_PATH] = {"unknown_component.log"};
#endif // OUTPUT_TO_SYSLOG_ENABLED


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

char *FormatData ( char *szTarget, char *szTitle, unsigned char *pData, int cbData, int bControlCharsOnly )
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
      if (bControlCharsOnly)
         FormatCharDisplayable ( szTarget, pData[i] );
      else
         FormatCharHex ( szTarget, pData[i] );
   }
   if (szTitle)
     sprintf(szTarget+strlen(szTarget),"<==");
#ifdef MK_WIN_EMUL
   SetThreadPriority(hThread,PrevPriority);
#endif
   return szTarget;
}

void app_trace_hex(char *pHeader, char *pData, int cbData)
{
  char *pTemp;
  size_t malloc_size;

  if (cbData<0)
    return;

  //
  // "<=="
  malloc_size =   (pHeader?strlen(pHeader):0) +       // Space for "%s"
                + (pHeader?(6+5+2):0) +               // Space for " (len=%d) "
                + (pHeader?3:0) +                     // Space for "==>"
                + (cbData*6)                          // Space for Max 6 bytes per character eg "<0x12>"
                + (pHeader?strlen(pHeader)+4+3:0) +   // Space for "<=="
                + 1;                                  // Space for trailing NULL

  pTemp = (char *)malloc(malloc_size);
  if (pTemp)
  {
    app_trace_zstring(FormatData(pTemp, pHeader, (unsigned char *)pData, cbData, TRUE));
    app_timer_delay(10);
    free(pTemp);
  }
  else
  {
    char tempStr[20];
#ifdef ALSO_LOG_INTERNAL_ERRORS
    app_trace_zstring_nocrlf("ERROR: Cannot display data do due malloc failure: ==>\"");
#else
    app_trace_zstring_nocrlf("Data ==>\"");
#endif
    app_trace_zstring_nocrlf(pHeader);
    app_trace_zstring_nocrlf("\", ");
    sprintf(tempStr, "%d bytes", cbData);
    app_trace_zstring_nocrlf(tempStr);
    app_trace_zstring("<==");
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
#endif

#ifdef OUTPUT_TO_SYSLOG_ENABLED
#include <syslog.h>

//void closelog(void);
//void openlog(const char *ident, int logopt, int facility);
//int setlogmask(int maskpri);
//void syslog(int priority, const char *message, ... /* arguments */);

void app_trace_openlog(const char *ident, int logopt, int facility)
{
   // e.g. logopt  : LOG_PID | LOG_CONS | LOG_PERROR
   //      facility: LOG_DAEMON or LOG_USER
   openlog(ident, logopt, facility);
}
void app_trace_closelog(void)
{
   closelog();
}
static void appendToLogfile(char *szString, bool emitCrLf)
{
    syslog(LOG_ERR, "%s%s", szString, emitCrLf?"\n":"");
    // LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO and LOG_DEBUG
}

#else // OUTPUT_TO_SYSLOG_ENABLED

void app_trace_openlog(const char *ident, int logopt, int facility)
{
}
void app_trace_closelog(void)
{
}

void setLogFilename(char *szPath, char *szFilename)
{
    strcpy(DEFAULTLOGFILEPATH, szPath);     // e.g. "/var/lib/<projectname>";
    strcpy(DEFAULTLOGFILENAME, szFilename); // e.g. "<projectname>_<component>.log"};
}

static const char *getLogFilename(char *szFilename)
{
    static char szLogFilename[_MAX_PATH];
#ifdef INCLUDE_WINDOWS_TYPE_FUNCTIONS
    const char *szTempPath = WinGetEnv("TEMP");
    strcpy(szLogFilename, szTempPath?szTempPath:"C:\\");
#else
    strcpy(szLogFilename, DEFAULTLOGFILEPATH);
#endif
    if (szLogFilename[strlen(szLogFilename)] != PATHSEPARATOR)
        strcat(szLogFilename, PATHSEPARATORSTR);
    strcat(szLogFilename, szFilename);
    return szLogFilename;
}

static void appendToLogfile(char *szString, bool emitCrLf)
{
    FILE *fLogfile;
    const char *pszLogFilename;
    static int bInitialised = FALSE;

    // We'll open and close every time for now, to aid debugging...
    pszLogFilename = getLogFilename(DEFAULTLOGFILENAME);
    if (!bInitialised)
    {
        printf("Appending to Logfile: \"%s\"\n",pszLogFilename);
    }
    fLogfile = fopen(pszLogFilename, "at");
    if (!fLogfile)
    {
        fLogfile = fopen(pszLogFilename, "wt");
    }
    if (!fLogfile)
    {
        if (errno == EACCES) // 13
            printf("FATAL: Error opening Logfile: \"%s\". errno=EACCES(13,Permission denied). Terminating.\n",pszLogFilename);
        else
            printf("FATAL: Error opening Logfile: \"%s\". errno=%d. Terminating.\n",pszLogFilename, errno);

        exit(3001);
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
#endif // OUTPUT_TO_SYSLOG_ENABLED
#endif // OUTPUT_TO_LOGFILE_ENABLED

#ifdef OUTPUT_TO_CONSOLE_ENABLED
static void OutputDebugStringA(char *szString)
{
    //printf(szString);
    int n = write(STDERR_FILENO, szString, strlen(szString));
    UNUSED_PARAM(n);
}
#endif // OUTPUT_TO_CONSOLE_ENABLED

void app_trace_zstring(char *szString)
{
    //TRACE ("msg=%s, int=%d\n", (LPCTSTR)sMsg, i);
    //OutputDebugString (LPCTSTR szMessage)
    //app_trace(szMessage);

#ifdef OUTPUT_TO_CONSOLE_ENABLED
    OutputDebugStringA(szString);
    OutputDebugStringA(EOL);
#endif

#ifdef OUTPUT_TO_LOGFILE_ENABLED
    // Append this to our log file
    appendToLogfile(szString, true);
#endif
}

void app_trace_zstring_nocrlf(char *szString)
{
#ifdef OUTPUT_TO_CONSOLE_ENABLED
    OutputDebugStringA(szString);
#endif

#ifdef OUTPUT_TO_LOGFILE_ENABLED
    // Append this to our log file
    appendToLogfile(szString, false);
#endif
}

void app_trace(char *szString)
{
    app_trace_zstring(szString);
}

int app_tracef(char *formatStr, ...)
{
#define SPRINTF_TRACE_BUFSIZE 4096
    va_list va;
    char *pBuf;
    int rc;

    pBuf = malloc(SPRINTF_TRACE_BUFSIZE);
    if (!pBuf)
        return -1;
    va_start(va, formatStr);
    rc = vsnprintf(pBuf, SPRINTF_TRACE_BUFSIZE, formatStr, va);
    if (rc == -1 || rc >= SPRINTF_TRACE_BUFSIZE)
        return -1;
    app_trace_zstring(pBuf);
    va_end(va);
    free(pBuf);
    return rc;
}

///////////////////////////////////////////////////////////////////////////////
// GetToken Functions
///////////////////////////////////////////////////////////////////////////////

int my_getToken(char *pSrcData, char *pDstField, int nFieldNum, int nDstFieldMaxLen)
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

    // JG: Why do we remove embedded spaces?
    // It is quite possible that an apn or username or password could
    // have embedded spaces.
    // I removed this condition and added a TrimLeading and TrimTrailing instead.
    //if ((pSrcData[i] != ' ') && (pSrcData[i] != '[') && (pSrcData[i] != ']'))
    {
      pDstField[j] = pSrcData[i];
      j++;
    }
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
    app_trace_zstring("TRACE: GetToken found token with zero length");
    app_timer_delay(10);
#endif
    return FALSE;
  }

  // JG: Added these TrimLeading and TrimTrailing instead
  // the previous code above which remeved all embedded spaces and
  // square braces.
  my_trimLeading(pDstField," [");
  my_trimTrailing(pDstField," ]");

  app_trace_hex ("TRACE: GetToken pSrcData=",pSrcData, (int)strlen(pSrcData));
  char buf[20];
  my_itoa (nFieldNum, buf, 10);
  app_trace_hex ("TRACE: GetToken nFieldNum=", buf, (int)strlen(buf));
  app_trace_hex ("TRACE: GetToken pDstField=", pDstField, (int)strlen(pDstField));
  app_timer_delay(10);

  return TRUE;
}