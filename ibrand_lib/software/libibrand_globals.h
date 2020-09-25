///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_LIBIBRAND_GLOBALS_H_
#define _INCLUDE_LIBIBRAND_GLOBALS_H_

#include <stdint.h>
#include "my_utils.h"

#define RANDSRC_USB          0
#define RANDSRC_IRONBRIDGE   1
#define IB_SOURCE_OF_RANDOMNESS RANDSRC_IRONBRIDGE

#define IBRAND_VENDOR_ID 0xFFFF
#define IBRAND_PRODUCT_ID 0xFFFF

#define FILELOCK_LOGLEVEL 0x00  // 0x01 is stdout, 0x02 is syslog

#endif // _INCLUDE_LIBIBRAND_GLOBALS_H_
