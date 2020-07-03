
///////////////////////////////////////////////////////////////////////////////
// Some Useful Utilities
// Copyright (c) 1998-2020 Jonathan Gilmore. All rights reserved.
// Original: J. Gilmore, Fri 02-Oct-1998, 16:11:57
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_MY_UTILS_H_
#define _INCLUDE_MY_UTILS_H_

#define DEBUG
//#define NDEBUG

#include <stdio.h>

#ifdef __linux__
   #define PATHSEPARATOR '/'
   #define PATHSEPARATORSTR "/"
   #define EOL "\n"
#elif _WIN32
   #define PATHSEPARATOR '\\'
   #define PATHSEPARATORSTR "\\"
   #define EOL "\r\n"
#endif

#ifdef __linux__
   #ifndef _MAX_PATH
      #ifdef MAX_PATH
         #define _MAX_PATH MAX_PATH
      #else
         #define _MAX_PATH 128
      #endif
   #endif
#endif

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#ifndef true
#define true 1
#define false 0
#endif
#ifndef BOOL
//typedef unsigned char BOOL;
#define BOOL unsigned char
#endif
#ifndef bool
//typedef unsigned char bool;
#define bool unsigned char
#endif

#ifndef SET_BIT
#define SET_BIT(x,n)  ((x) |=  ((1)<<(n)))
#define CLR_BIT(x,n)  ((x) &= ~((1)<<(n)))
#define TEST_BIT(x,n) ((x) &   ((1)<<(n)))
#endif

#ifndef UNUSED_PARAM
#define UNUSED_PARAM(x) (void)(x)
#endif
#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif
#ifndef NOTUSED
#define NOTUSED(x) (void)(x)
#endif

///////////////////////////////////////////////////////////////////////////////
// Utility Functions
///////////////////////////////////////////////////////////////////////////////
extern int    my_minimum(int x,int y);
extern char * my_strrev(char *string);
extern void   my_itoa(int data,char *dst,char non);
extern int    my_abs(int x);
extern char * my_strlcpy( char *strDest, const char *strSource, size_t count );
extern char * my_strstri(char *pBuffer, char *pSearchStr);
extern void   my_translateCharactersInString(char *szString,char *szOldChars,char *szNewChars);
extern BOOL   my_isInSetOfChars(int ch, char *szSetOfChars);
extern char * my_trimTrailing(char *szStr, char *szSetOfChars);
extern char * my_trimLeading(char *szStr, char *szSetOfChars);
extern BOOL   my_isWhitespace(int ch);
extern char * my_trimTrailingWhiteSpace(char *szStr);
extern char * my_trimLeadingWhiteSpace(char *szStr);
extern char * my_removeTrailingString(char *szStr, char *szStrToRemove);
extern char * my_removeTrailingStringi(char *szStr, char *szStrToRemove);
extern long   my_getFilesize(const char *szFilename);
extern bool   my_fileExists(const char *szFilename);

#endif // _INCLUDE_MY_UTILS_H_