#pragma once

#include "std_types_cfg.h"

#ifdef WINDOWS
#include <basetsd.h>
#endif

#ifndef WINDOWS 
#define UINT64 unsigned long long
#define ULONG64 unsigned long long
#define UINT32 unsigned long
#define ULONG32 unsigned long
#define UINT16 unsigned short
#define UINT8 unsigned char
#define USHORT unsigned short
#define UCHAR unsigned char
#endif

#define PLATFORM_ENDIAN LITTLEENDIAN

#ifndef WINDOWS
#include <unistd.h>
#define Sleep(ms) usleep(ms*1000)
#endif
