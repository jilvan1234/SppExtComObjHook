#pragma once

#include "targetver.h"
#include <Windows.h>

// KMS V4 Rijndael-160 CMAC
void WINAPI GetV4Cmac(int MessageSize, const BYTE *Message, BYTE *HashOut);

// KMS V5/V6 AES-128 CBC encryption
BOOL WINAPI AesEncryptMessage(DWORD Version, const BYTE *IV, BYTE *Message, DWORD *MessageSize, DWORD MessageBufLen);

// KMS V5/V6 AES-128 CBC decryption
BOOL WINAPI AesDecryptMessage(DWORD Version, const BYTE *IV, BYTE *Message, DWORD *MessageSize);

#define TIMESTAMP_TOLERANCE 0x00000022816889bdULL

// KMS V5/V6 SHA-256 hash
BOOL WINAPI GetSha256Hash(const BYTE *data, DWORD dataSize, BYTE *Hash);

// KMS V6 HMAC-SHA256 key
void WINAPI GetHmacKey(const ULONG64 *TimeStamp, BYTE *Key);

// KMS V6 HMAC-SHA256
BOOL WINAPI GetHmacSha256(const BYTE *pbKey, DWORD dwDataLen, const BYTE *pbData, BYTE *pbHash);

// PRNG using Win32 Crypto API provider
BOOL WINAPI GetRandomBytes(BYTE *RandomBuffer, DWORD RandomBufferLength);

// Xor 16-bytes source into destination
void WINAPI XorBuffer(const BYTE *source, BYTE *destination);
