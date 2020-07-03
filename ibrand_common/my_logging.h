
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

#ifndef _INCLUDE_MY_LOGGING_H_
#define _INCLUDE_MY_LOGGING_H_

#define DEBUG
//#define NDEBUG

#include "stdio.h"


#if defined(DEBUG) && !defined(NDEBUG)
#define dbg_stmnt(x)  x
#define dbg_printf(type, ...) (((type) & xdbg_current_types) ? printf (__VA_ARGS__) : 0)
#else /* defined(DEBUG) && !defined(NDEBUG) */
#define dbg_stmnt(x)
#define dbg_printf(...)
#endif /* defined(DEBUG) && !defined(NDEBUG) */

#define PRINTLN_INT(token) printf(#token " = %d\r\n", token)
#define PRINTLN_UINT(token) printf(#token " = %u\r\n", token)
#define PRINTLN_ZSTR(token) printf(#token " = \"%s\"\r\n", token)
#define PRINTLN_CHAR(token) printf(#token " = '%c'\r\n", token)

///////////////////////////////////////////////////////////////////////////////
// Logging Functions
///////////////////////////////////////////////////////////////////////////////
extern void   setLogFilename(char *szPath, char *szFilename);
extern char * FormatData ( char *szTarget, char *szTitle, unsigned char *pData, int cbData, int bControlCharsOnly );
extern void   app_trace_openlog(const char *ident, int logopt, int facility);
extern void   app_trace_closelog(void);
extern void   app_trace_hex(char *pHeader, char *pData, int cbData);
extern void   app_trace_zstring(char *szString);
extern void   app_trace_zstring_nocrlf(char *szString);
extern void   app_trace(char *szString);
extern int    app_tracef(char *formatStr, ...);
extern int    my_getToken(char *pSrcData, char *pDstField, int nFieldNum, int nDstFieldMaxLen);

#endif // _INCLUDE_MY_LOGGING_H_
