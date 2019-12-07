#pragma once

#define _WIN32_MAXVER           0x0601
#define _WIN32_WINDOWS_MAXVER   0x0601
#define NTDDI_MAXVER            0x06010000
#define _WIN32_IE_MAXVER        0x0800
#define _WIN32_WINNT_MAXVER     0x0601
#define WINVER_MAXVER           0x0601

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x05010300
#endif

#include <SDKDDKVer.h>

struct IUnknown; // Workaround for "combaseapi.h(229): error C2760: syntax error: unexpected token 'identifier', expected 'type specifier'" when using /permissive-

#ifndef _NO_CRT_STDIO_INLINE
#define _NO_CRT_STDIO_INLINE 1
#endif
