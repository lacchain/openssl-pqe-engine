///////////////////////////////////////////////////////////////////////////////
// Base64 encode/decode Utilities
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_MY_BASE64_H_
#define _INCLUDE_MY_BASE64_H_

extern char* base64_encode(const unsigned char *data, size_t input_length, size_t *poutput_length);
extern unsigned char* base64_decode(const char *data, size_t input_length, size_t *poutput_length);

#endif // _INCLUDE_MY_BASE64_H_
