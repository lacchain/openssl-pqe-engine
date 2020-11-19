
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


// Detail of last error
int my_errno = 0; // We'll use the std errno values e.g. ENOMEM, EINVAL, ERANGE, ENOTSUPP, etc

///////////////////////////////////////////////////////////////////////////////
// Utility Functions
///////////////////////////////////////////////////////////////////////////////

int my_minimum(int x, int y)
{
  return (x<y)?x:y;
}

size_t my_minimum_size_t (size_t x, size_t y)
{
    return (x < y) ? x : y;
}

char *my_strrev(char *string)
{
  char *start = string;
  char *left = string;

  while (*string++); // find end of string

  string -= 2;
  while (left < string)
  {
    char ch = *left;
    *left++ = *string;
    *string-- = ch;
  }
  return(start);
}

void my_itoa(int data, char *dst, char non)
{
  UNUSED_PARAM(non); // Avoid compiler warning
  sprintf(dst,"%d",data);
}

int my_abs(int x)
{
  return (x<0)?(-x):(x);
}

char *my_strstri(char *pBuffer, char *pSearchStr)
{
  char *pBuffPtr = pBuffer;

  while (*pBuffPtr != 0x00)
  {
    char *pCompareOne = pBuffPtr;
    char *pCompareTwo = pSearchStr;

    while (tolower(*pCompareOne) == tolower(*pCompareTwo))
    {
      pCompareOne++;
      pCompareTwo++;

      if (*pCompareTwo == 0x00)
        return (char *)pBuffPtr;
    }
    pBuffPtr++;
  }
  return NULL;
}

int my_stricmpL(char const *a, char const *b)
{
  while (*a)
  {
    int d = tolower(*a) - tolower(*b);
    if (d)
    {
        return d;
    }
    a++;
    b++;
  }
  return 0;
}

int my_stricmpU(char const *a, char const *b)
{
  while (*a)
  {
    int d = toupper(*a) - toupper(*b);
    if (d)
    {
        return d;
    }
    a++;
    b++;
  }
  return 0;
}

int my_stricmp(char const *a, char const *b)
{
    // https://stackoverflow.com/questions/5820810/case-insensitive-string-comp-in-c
    // Comparing as lower or as upper case:
    //    Both my_stricmpL and my_stricmpU will return 0 with my_stricmpL("A", "a") and my_stricmpU("A", "a").
    //    But my_stricmpL("A", "_") and my_stricmpU("A", "_") can return different signed results.
    //    This is because '_' is often between the upper and lower case letters, as it is in ASCII.
    // We'll arbitrarily choose lowercase.
    return my_stricmpL(a, b);
}

void my_translateCharactersInString(char *szString,char *szOldChars,char *szNewChars)
{
  unsigned int i;
  unsigned int j;
  unsigned int TranslationCharsLen;

  TranslationCharsLen = (unsigned int)my_minimum_size_t(strlen(szOldChars),strlen(szNewChars));

  for (i=0; i<strlen(szString); i++)
  {

    // Debugging/Testing
    if ((szOldChars[0] == '.') && (szString[i] == ','))
      (void)szString[i]; // Dummy statement

    // Debugging/Testing
    if (szString[i] == '$')
      (void)szString[i]; // Dummy statement

    for (j=0; j<TranslationCharsLen; j++)
    {
       if (szString[i] == szOldChars[j])
         szString[i] = szNewChars[j];
    }
  }
}

BOOL my_isInSetOfChars(int ch, char *szSetOfChars)
{
  unsigned int i;

  for (i=0;i<strlen(szSetOfChars);i++)
  {
    if (ch == szSetOfChars[i])
      return TRUE;
  }
  return FALSE;
}

char *my_trimTrailing(char *szStr, char *szSetOfChars)
{
  while(strlen(szStr) && my_isInSetOfChars(szStr[strlen(szStr)-1],szSetOfChars))
    szStr[strlen(szStr)-1] = 0;
  return szStr;
}

char *my_trimLeading(char *szStr, char *szSetOfChars)
{
  my_strrev(szStr);
  my_trimTrailing(szStr,szSetOfChars);
  my_strrev(szStr);
  return szStr;
}

BOOL my_isWhitespace(int ch)
{
  if ((ch == ' ' ) ||
      (ch == '\t') ||
      (ch == '\r') ||
      (ch == '\n'))
    return TRUE;
  return FALSE;
}

char *my_trimTrailingWhiteSpace(char *szStr)
{
  while(strlen(szStr) && my_isWhitespace(szStr[strlen(szStr)-1]))
    szStr[strlen(szStr)-1] = 0;
  return szStr;
}

char *my_trimLeadingWhiteSpace(char *szStr)
{
  my_strrev(szStr);
  my_trimTrailingWhiteSpace(szStr);
  my_strrev(szStr);
  return szStr;
}

char *my_removeTrailingString(char *szStr, char *szStrToRemove)
{
  if (szStr && strlen(szStr) && szStrToRemove && strlen(szStrToRemove))
  {
    char *p = strstr(szStr,szStrToRemove);
    if (p && (p==(szStr+strlen(szStr)-strlen(szStrToRemove))))
    {
       *p = 0;
    }
  }
  return szStr;
}

char *my_removeTrailingStringi(char *szStr, char *szStrToRemove)
{
  if (szStr && strlen(szStr) && szStrToRemove && strlen(szStrToRemove))
  {
    char *p = my_strstri(szStr,szStrToRemove);
    if (p && (p==(szStr+strlen(szStr)-strlen(szStrToRemove))))
    {
       *p = 0;
    }
  }
  return szStr;
}

char *my_strlcpy( char *strDest, const char *strSource, size_t count )
{
  // Copies at most count bytes from strSource to strDest,
  // and always adds a trailing NULL.

  // In strncpy, if count is less than or equal to
  // the length of strSource, a null character is
  // not appended automatically to strDest.
  // So we will add it here.
  // NB strDest must be at least (count+1) is size.

  strncpy(strDest,strSource,count);
  if (count<=strlen(strSource))
    strDest[count] = 0;
  return strDest;
}

long my_getFilesize(const char *szFilename)
{
    FILE *fIn;
    long filesize;

    // Open the file
    fIn = fopen(szFilename,"rb");
    if (fIn == NULL)
    {
        return -1;
    }

    fseek (fIn, 0, SEEK_END);
    filesize = (long)ftell(fIn);
    rewind(fIn);
    fclose(fIn);
    return filesize;
}

bool my_fileExists(const char *szFilename)
/*+---------------------------------------------------------+*/
/*                                                           */
/*+---------------------------------------------------------+*/
{
    if (access(szFilename, F_OK) != -1) // From unistd.h
    {
        // File exists
        return true;
    }
    // File does not exist
    return false;
}



// void my_hashOfString(char *szSrcStr, char *szDstStr, size_t cbDstStr)
// {
//     struct MD5Context context;
//     unsigned char digest[16];
//     MD5Init(&context);
//     MD5Update(&context, szSrcStr, strlen(szSrcStr));
//     MD5Final(digest, &context);
//     my_strlcpy(szDstStr, (char *)digest, cbDstStr);
// }

int my_roundUp(int num, int multipleOf)
{
    // Return a number which is a whole multiple of N
    // e.g. newlen = RoundUp (oldlen, 16);

    int newlen = num;

    if (num % multipleOf)
    {
        newlen += multipleOf - (num % multipleOf);
    }
    return newlen;
}

bool my_isSuperUser(void)
{
    return (geteuid() == 0);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------
