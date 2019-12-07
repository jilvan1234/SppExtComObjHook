#pragma once

#include "targetver.h"
#include <Windows.h>
#include <time.h>
#include "crypto.h"
#include "kms.h"
#include "defines.h"

// KMS server settings
KMSServerSettings Settings = {
	// KMS Enabled Flag
	TRUE,
	// Activation Interval
	DEFAULT_AI,
	// Renewal Interval
	DEFAULT_RI,
	// KMS Host HWID
	DEFAULT_HWID,
	// PIDs
	{ RANDOM_PID, RANDOM_PID, RANDOM_PID }
};

// Known Application IDs
GUIDName AppIDList[] =
{
	{ { 0 }, L"Windows" },
	{ { 0 }, L"Office2010" },
	{ { 0 }, L"Office2013" },
	{ { 0 }, L"Office2016" },
	{ { 0 }, L"Office2019" },
	{ { 0 }, nullptr }
};

#pragma region Response

// Unknown 8-bytes data (seems not to affect activation)
// const BYTE Unknown8[8] = { 0x3A, 0x1C, 0x04, 0x96, 0x00, 0xB6, 0x00, 0x76 };

// Pack KMSBaseResponse into Byte Packet
int WINAPI PackBaseResponse(BYTE *response, const KMSBaseResponse *BaseResponse)
{
	BYTE *next = response;

	size_t CopySize = sizeof(BaseResponse->Version)
		+ sizeof(BaseResponse->PIDSize)
		+ BaseResponse->PIDSize;

	memcpy(next, &BaseResponse->Version, CopySize);
	next += CopySize;

	CopySize = sizeof(BaseResponse->CMID)
		+ sizeof(BaseResponse->TimeStamp)
		+ sizeof(BaseResponse->CurrentCount)
		+ sizeof(BaseResponse->VLActivationInterval)
		+ sizeof(BaseResponse->VLRenewalInterval);

	memcpy(next, &BaseResponse->CMID, CopySize);
	next += CopySize;

	return (int)(next - response);
}

// Create Base Response from Base Request
void WINAPI CreateBaseResponse(KMSBaseRequest *BaseRequest, KMSBaseResponse *BaseResponse)
{
	// Version
	BaseResponse->Version = BaseRequest->Version;

	// Set extended PID and PID size
	GetKMSPID(BaseResponse->PIDData, BaseRequest);
	BaseResponse->PIDSize = ((DWORD)wcslen(BaseResponse->PIDData) + 1) << 1;

	// CMID
	BaseResponse->CMID = BaseRequest->CMID;

	// TimeStamp
	BaseResponse->TimeStamp = BaseRequest->TimeStamp;

	// Machine Count
	BaseResponse->CurrentCount = BaseRequest->RequiredCount << 1;

	// Intervals
	BaseResponse->VLActivationInterval = Settings.ActivationInterval;
	BaseResponse->VLRenewalInterval = Settings.RenewalInterval;

	SYSTEMTIME st;
	FileTimeToSystemTime(&BaseRequest->TimeStamp, &st);
	OutputDebugStringEx(L"[KMS Info] Protocol Version   : %i.%i\n", BaseRequest->MajorVer, BaseRequest->MinorVer);
	OutputDebugStringEx(L"[KMS Info] License Status     : %u\n", BaseRequest->LicenseStatus);
	OutputDebugStringEx(L"[KMS Info] Remaining Period   : %u minutes\n", BaseRequest->RemainingGrace);
	OutputDebugStringEx(L"[KMS Info] VM / VHD Boot      : %i\n", BaseRequest->VMInfo);
	OutputDebugStringEx(L"[KMS Info] Application ID     : {"GUID_FORMAT"}\n", GUID_ARG(BaseRequest->AppID));
	OutputDebugStringEx(L"[KMS Info] Activation ID      : {"GUID_FORMAT"}\n", GUID_ARG(BaseRequest->SkuID));
	OutputDebugStringEx(L"[KMS Info] KMS Counted ID     : {"GUID_FORMAT"}\n", GUID_ARG(BaseRequest->KmsID));
	OutputDebugStringEx(L"[KMS Info] Client Machine ID  : {"GUID_FORMAT"}\n", GUID_ARG(BaseRequest->CMID));
	OutputDebugStringEx(L"[KMS Info] Previous CMID      : {"GUID_FORMAT"}\n", GUID_ARG(BaseRequest->CMID_prev));
	OutputDebugStringEx(L"[KMS Info] Workstation Name   : %ls\n", BaseRequest->MachineName);
	OutputDebugStringEx(L"[KMS Info] TimeStamp (UTC)    : %04d/%02d/%02d %02d:%02d:%02d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	OutputDebugStringEx(L"[KMS Info] Request N Count    : %u minimum clients\n", BaseRequest->RequiredCount);
	OutputDebugStringEx(L"[KMS Info] Response N Count   : %u activated clients\n", BaseResponse->CurrentCount);
	OutputDebugStringEx(L"[KMS Info] Activation Interval: %u minutes\n", BaseResponse->VLActivationInterval);
	OutputDebugStringEx(L"[KMS Info] Renewal Interval   : %u minutes\n", BaseResponse->VLRenewalInterval);
	OutputDebugStringEx(L"[KMS Info] KMS Host ePID      : %ls\n", BaseResponse->PIDData);

	return;
}

// Create KMS Response V4
BYTE * WINAPI CreateResponseV4(int requestSize, BYTE *request, int *responseSize, KMSBaseRequest *gotRequest, KMSBaseResponse *sentResponse)
{
	UNREFERENCED_PARAMETER(requestSize);

	// Get KMS Base Request Object
	KMSBaseRequest BaseRequest = ((KMSV4Request *)request)->BaseRequest;

	// Prepare a Workspace Buffer
	BYTE buffer[MAX_RESPONSE_SIZE];

	// Create BaseResponse
	KMSBaseResponse BaseResponse;
	CreateBaseResponse(&BaseRequest, &BaseResponse);

	// Pack BaseResponse
	int size = PackBaseResponse(buffer, &BaseResponse);

	// Generate Hash Signature
	GetV4Cmac(size, buffer, buffer + size);

	// Put Response Size
	*responseSize = size + 16;

	// Put Response Data
	BYTE *response = (BYTE *)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return the Got Request and the Response to be sent
	memcpy(gotRequest, &BaseRequest, sizeof(KMSBaseRequest));
	memcpy(sentResponse, &BaseResponse, sizeof(KMSBaseResponse));

	// Return Created Response
	return response;
}

// Create KMS Response V5 and V6
BYTE * WINAPI CreateResponseV6(int requestSize, BYTE *request, int *responseSize, KMSBaseRequest *gotRequest, KMSBaseResponse *sentResponse)
{
	// Get KMS V5/V6 Request Object
	KMSV6Request *Request = (KMSV6Request *)request;

	// Prepare a Workspace Buffer
	BYTE buffer[MAX_RESPONSE_SIZE];
	BYTE *next = buffer;

	// Version
	*(DWORD *)next = Request->Version;
	next += sizeof(Request->Version);

	// Response IV (same as Request in V5, random in V6)
	BYTE *ResponseIV = next, ResponseIVData[16];

	if (Request->Version == KMS_VERSION_5)
	{
		// Use same IV as request
		memcpy(next, Request->IV, sizeof(Request->IV));
		next += sizeof(Request->IV);
	}
	else
	{
		// Get Random IV
		GetRandomBytes(ResponseIVData, sizeof(ResponseIVData));

		// First we put decrypted Response IV for HMAC-SHA256
		DWORD DecryptSize = sizeof(ResponseIVData);
		memcpy(next, ResponseIVData, sizeof(ResponseIVData));
		AesDecryptMessage(Request->Version, nullptr, next, &DecryptSize);
		next += sizeof(ResponseIVData);
	}

	// AES Decryption (Decrypted Salt is also needed)
	DWORD DecryptSize = requestSize - sizeof(Request->Version);
	AesDecryptMessage(Request->Version, nullptr, Request->IV, &DecryptSize);

	// Create BaseResponse
	KMSBaseResponse BaseResponse;
	CreateBaseResponse(&Request->BaseRequest, &BaseResponse);

	// Pack BaseResponse
	BYTE *encryption_start = next;
	next += PackBaseResponse(next, &BaseResponse);

	// Random Key
	GetRandomBytes(next, 16);

	// SHA-256
	GetSha256Hash(next, 16, next + 16);

	// Xor
	XorBuffer(Request->IV, next);

	next += 48; // sizeof(RandomSalt) + sizeof(SHA256)

	if (Request->Version == KMS_VERSION_6)
	{
		// Unknown8
		// memcpy(next, Unknown8, sizeof(Unknown8));
		// next += sizeof(Unknown8);
		*(QWORD *)next = Settings.KMSHWID;
		next += sizeof(Settings.KMSHWID);
		OutputDebugStringEx(L"[KMS Info] KMS Host HWID      : %016I64X\n", Settings.KMSHWID);

		// Xor2
		memcpy(next, Request->IV, sizeof(Request->IV));
		next += sizeof(Request->IV);

		// HmacSHA256
		DWORD HmacDataLen = (DWORD)(next - ResponseIV);
		BYTE HmacKey[16], HMacSHA256[32];
		GetHmacKey((ULONG64 *)&BaseResponse.TimeStamp, HmacKey);
		GetHmacSha256(HmacKey, HmacDataLen, ResponseIV, HMacSHA256);
		memcpy(next, &HMacSHA256[16], 16);
		next += 16;

		// Put back the plaintext response IV
		memcpy(ResponseIV, ResponseIVData, sizeof(ResponseIVData));
	}

	// Encrypt Response
	DWORD encryptSize = (DWORD)(next - encryption_start);
	AesEncryptMessage(Request->Version, ResponseIV, encryption_start, &encryptSize, MAX_RESPONSE_SIZE - 20);

	// Put Created Response into RPC Buffer
	*responseSize = encryptSize + 20;
	BYTE *response = (BYTE *)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return the Got Request and the Response to be sent
	memcpy(gotRequest, &Request->BaseRequest, sizeof(KMSBaseRequest));
	memcpy(sentResponse, &BaseResponse, sizeof(KMSBaseResponse));

	// Return Created Response
	return response;
}

// Create KMS Response from Got Request
BYTE * WINAPI CreateResponse(int requestSize, BYTE *request, int *responseSize, KMSBaseRequest *gotRequest, KMSBaseResponse *sentResponse)
{
	// KMS Protocol Version
	switch (((DWORD *)request)[0])
	{
	case KMS_VERSION_4:
		return CreateResponseV4(requestSize, request, responseSize, gotRequest, sentResponse);

	case KMS_VERSION_5:
	case KMS_VERSION_6:
		return CreateResponseV6(requestSize, request, responseSize, gotRequest, sentResponse);

	default:
		return nullptr;
	}
}

#pragma endregion Response

// -----------------------------------------------------------------------------------
// RPC Function to Build and Send a KMS Server Response
// -----------------------------------------------------------------------------------
int WINAPI ActivationResponse(int requestSize, unsigned char *request, int *responseSize, unsigned char **response)
{
	// Verify Request Size
	if (requestSize < 92)
	{
		*responseSize = 0;
		*response = nullptr;
		return RPC_S_INVALID_ARG;
	}

	// Hold Request and Response for Logging
	KMSBaseRequest gotRequest;
	KMSBaseResponse sentResponse;

	// Send Response and Response Size
	*response = CreateResponse(requestSize, request, responseSize, &gotRequest, &sentResponse);

	return RPC_S_OK;
}

#pragma region RandomKMSPID

// HostType, OSBuild and Minimum possible activation date (in UTC seconds)
const struct KMSHostOS { WORD Type; WORD Build; WORD MinimumDay; WORD MinimumYear; time_t CsvlkTime; } HostOS[] =
{
	{ 55041, 6002,  146, 2009, (time_t)1243296000LL},    // Windows Server 2008     : 2009/05/26 SP2 GA
	{ 55041, 7601,   53, 2011, (time_t)1311292800LL},    // Windows Server 2008 R2  : 2011/02/22 SP1 GA
	{ 5426,  9200,  248, 2012, (time_t)1346716800LL},    // Windows Server 2012     : 2012/09/04 RTM GA
	{ 6401,  9600,  290, 2013, (time_t)1381968000LL},    // Windows Server 2012 R2  : 2013/10/17 RTM GA
	{ 3612,  14393, 286, 2016, (time_t)1476230400LL},    // Windows Server 2016     : 2016/10/12 RTM GA
	{ 3612,  17763, 275, 2018, (time_t)1538438400LL}     // Windows Server 2019     : 2018/10/02 RTM GA
};
#define HOST_SERVER2008   0
#define HOST_SERVER2008R2 1
#define HOST_SERVER2012   2
#define HOST_SERVER2012R2 3
#define HOST_SERVER2016   4
#define HOST_SERVER2019   5

// CSVLK GroupID and PIDRange
const struct PKEYCONFIG { WORD GroupID; DWORD RangeMin; DWORD RangeMax; } pkeyconfig[] =
{
	{ 152, 381000000, 392999999 }, // Windows Server 2008 C
	{ 168, 305000000, 312119999 }, // Windows Server 2008 R2 C
	{ 206, 152000000, 191999999 }, // Windows Server 2012
	{ 206, 271000000, 310999999 }, // Windows Server 2012 R2
	{ 206, 491000000, 530999999 }, // Windows Server 2016
	{ 206, 551000000, 570999999 }, // Windows Server 2019
	{ 96,  199000000, 217999999 }, // Office 2010
	{ 206, 234000000, 255999999 }, // Office 2013
	{ 206, 437000000, 458999999 }, // Office 2016
	{ 206, 666000000, 685999999 }, // Office 2019
	{ 206, 2835000, 2854999 },     // Windows Server 2019 VL Retail
	{ 3858, 0, 14999999 }          // Windows 10 China Government
};
#define PKEYCONFIG_SERVER2008_CSVLK   0
#define PKEYCONFIG_SERVER2008R2_CSVLK 1
#define PKEYCONFIG_SERVER2012_CSVLK   2
#define PKEYCONFIG_SERVER2012R2_CSVLK 3
#define PKEYCONFIG_SERVER2016_CSVLK   4
#define PKEYCONFIG_SERVER2019_CSVLK   5
#define PKEYCONFIG_OFFICE2010_CSVLK   6
#define PKEYCONFIG_OFFICE2013_CSVLK   7
#define PKEYCONFIG_OFFICE2016_CSVLK   8
#define PKEYCONFIG_OFFICE2019_CSVLK   9
#define PKEYCONFIG_SERVER2019R_CSVLK  10
#define PKEYCONFIG_WIN10GOV_CSVLK     11

// KmsCountedIdList
const GUID APP_ID_WINDOWS  =                 {0x55C92734, 0xD682, 0x4D71, {0x98, 0x3E, 0xD6, 0xEC, 0x3F, 0x16, 0x05, 0x9F}};
const GUID APP_ID_OFFICE14 =                 {0x59A52881, 0xA989, 0x479D, {0xAF, 0x46, 0xF2, 0x75, 0xC6, 0x37, 0x06, 0x63}};
const GUID APP_ID_OFFICE15 =                 {0x0FF1CE15, 0xA989, 0x479D, {0xAF, 0x46, 0xF2, 0x75, 0xC6, 0x37, 0x06, 0x63}};
const GUID KMS_ID_OFFICE_2010 =              {0xE85AF946, 0x2E25, 0x47B7, {0x83, 0xE1, 0xBE, 0xBC, 0xEB, 0xEA, 0xC6, 0x11}};
const GUID KMS_ID_OFFICE_2013 =              {0xE6A6F1BF, 0x9D40, 0x40C3, {0xAA, 0x9F, 0xC7, 0x7B, 0xA2, 0x15, 0x78, 0xC0}};
const GUID KMS_ID_OFFICE_2016 =              {0x85B5F61B, 0x320B, 0x4BE3, {0x81, 0x4A, 0xB7, 0x6B, 0x2B, 0xFA, 0xFC, 0x82}};
const GUID KMS_ID_OFFICE_2019 =              {0x617D9EB1, 0xEF36, 0x4F82, {0x86, 0xE0, 0xA6, 0x5A, 0xE0, 0x7B, 0x96, 0xC6}};
const GUID KMS_ID_WINDOWS_VISTA =            {0x212A64DC, 0x43B1, 0x4D3D, {0xA3, 0x0C, 0x2F, 0xC6, 0x9D, 0x20, 0x95, 0xC6}};
const GUID KMS_ID_WINDOWS_7 =                {0x7FDE5219, 0xFBFA, 0x484A, {0x82, 0xC9, 0x34, 0xD1, 0xAD, 0x53, 0xE8, 0x56}};
const GUID KMS_ID_WINDOWS_8_RETAIL =         {0xBBB97B3B, 0x8CA4, 0x4A28, {0x97, 0x17, 0x89, 0xFA, 0xBD, 0x42, 0xC4, 0xAC}};
const GUID KMS_ID_WINDOWS_8_VOLUME =         {0x3C40B358, 0x5948, 0x45AF, {0x92, 0x3B, 0x53, 0xD2, 0x1F, 0xCC, 0x7E, 0x79}};
const GUID KMS_ID_WINDOWS_81_RETAIL =        {0x6D646890, 0x3606, 0x461A, {0x86, 0xAB, 0x59, 0x8B, 0xB8, 0x4A, 0xCE, 0x82}};
const GUID KMS_ID_WINDOWS_81_VOLUME =        {0xCB8FC780, 0x2C05, 0x495A, {0x97, 0x10, 0x85, 0xAF, 0xFF, 0xC9, 0x04, 0xD7}};
const GUID KMS_ID_WINDOWS_10_RETAIL =        {0xE1C51358, 0xFE3E, 0x4203, {0xA4, 0xA2, 0x3B, 0x6B, 0x20, 0xC9, 0x73, 0x4E}};
const GUID KMS_ID_WINDOWS_10_VOLUME =        {0x58E2134F, 0x8E11, 0x4D17, {0x9C, 0xB2, 0x91, 0x06, 0x9C, 0x15, 0x11, 0x48}};
const GUID KMS_ID_WINDOWS_10_UNKNOWN =       {0xD27CD636, 0x1962, 0x44E9, {0x8B, 0x4F, 0x27, 0xB6, 0xC2, 0x3E, 0xFB, 0x85}};
const GUID KMS_ID_WINDOWS_10_LTSB_2016 =     {0x969FE3C0, 0xA3EC, 0x491A, {0x9F, 0x25, 0x42, 0x36, 0x05, 0xDE, 0xB3, 0x65}};
const GUID KMS_ID_WINDOWS_10_LTSC_2019 =     {0x11B15659, 0xE603, 0x4CF1, {0x9C, 0x1F, 0xF0, 0xEC, 0x01, 0xB8, 0x18, 0x88}};
const GUID KMS_ID_WINDOWS_10_GOV =           {0x7BA0BF23, 0xD0F5, 0x4072, {0x91, 0xD9, 0xD5, 0x5A, 0xF5, 0xA4, 0x81, 0xB6}};
const GUID KMS_ID_WINDOWS_SERVER_2008A =     {0x33E156E4, 0xB76F, 0x4A52, {0x9F, 0x91, 0xF6, 0x41, 0xDD, 0x95, 0xAC, 0x48}};
const GUID KMS_ID_WINDOWS_SERVER_2008B =     {0x8FE53387, 0x3087, 0x4447, {0x89, 0x85, 0xF7, 0x51, 0x32, 0x21, 0x5A, 0xC9}};
const GUID KMS_ID_WINDOWS_SERVER_2008C =     {0x8A21FDF3, 0xCBC5, 0x44EB, {0x83, 0xF3, 0xFE, 0x28, 0x4E, 0x66, 0x80, 0xA7}};
const GUID KMS_ID_WINDOWS_SERVER_2008R2A =   {0x0FC6CCAF, 0xFF0E, 0x4FAE, {0x9D, 0x08, 0x43, 0x70, 0x78, 0x5B, 0xF7, 0xED}};
const GUID KMS_ID_WINDOWS_SERVER_2008R2B =   {0xCA87F5B6, 0xCD46, 0x40C0, {0xB0, 0x6D, 0x8E, 0xCD, 0x57, 0xA4, 0x37, 0x3F}};
const GUID KMS_ID_WINDOWS_SERVER_2008R2C =   {0xB2CA2689, 0xA9A8, 0x42D7, {0x93, 0x8D, 0xCF, 0x8E, 0x9F, 0x20, 0x19, 0x58}};
const GUID KMS_ID_WINDOWS_SERVER_2012 =      {0x8665CB71, 0x468C, 0x4AA3, {0xA3, 0x37, 0xCB, 0x9B, 0xC9, 0xD5, 0xEA, 0xAC}};
const GUID KMS_ID_WINDOWS_SERVER_2012R2 =    {0x8456EFD3, 0x0C04, 0x4089, {0x87, 0x40, 0x5B, 0x72, 0x38, 0x53, 0x5A, 0x65}};
const GUID KMS_ID_WINDOWS_SERVER_2016 =      {0x6E9FC069, 0x257D, 0x4BC4, {0xB4, 0xA7, 0x75, 0x05, 0x14, 0xD3, 0x27, 0x43}};
const GUID KMS_ID_WINDOWS_SERVER_2019 =      {0x8449B1FB, 0xF0EA, 0x497A, {0x99, 0xAB, 0x66, 0xCA, 0x96, 0xE9, 0xA0, 0xF5}};
/*
e85af946-2e25-47b7-83e1-bebcebeac611 - Office 2010
e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0 - Office 2013
85b5f61b-320b-4be3-814a-b76b2bfafc82 - Office 2016
617d9eb1-ef36-4f82-86e0-a65ae07b96c6 - Office 2019
212a64dc-43b1-4d3d-a30c-2fc69d2095c6 - Windows Vista
7fde5219-fbfa-484a-82c9-34d1ad53e856 - Windows 7
bbb97b3b-8ca4-4a28-9717-89fabd42c4ac - Windows 8 (Retail)
3c40b358-5948-45af-923b-53d21fcc7e79 - Windows 8 (Volume)
6d646890-3606-461a-86ab-598bb84ace82 - Windows 8.1 (Retail)
cb8fc780-2c05-495a-9710-85afffc904d7 - Windows 8.1 (Volume)
e1c51358-fe3e-4203-a4a2-3b6b20c9734e - Windows 10 (Retail)
58e2134f-8e11-4d17-9cb2-91069c151148 - Windows 10 (Volume)
d27cd636-1962-44e9-8b4f-27b6c23efb85 - Windows 10 (Volume) Unknown
969fe3c0-a3ec-491a-9f25-423605deb365 - Windows 10 (Volume) 2016
11b15659-e603-4cf1-9c1f-f0ec01b81888 - Windows 10 (Volume) 2019
7ba0bf23-d0f5-4072-91d9-d55af5a481b6 - Windows 10 China Government
33e156e4-b76f-4a52-9f91-f641dd95ac48 - Windows Server 2008 A (Web and HPC)
8fe53387-3087-4447-8985-f75132215ac9 - Windows Server 2008 B (Standard and Enterprise)
8a21fdf3-cbc5-44eb-83f3-fe284e6680a7 - Windows Server 2008 C (Datacenter)
0fc6ccaf-ff0e-4fae-9d08-4370785bf7ed - Windows Server 2008 R2 A (Web and HPC)
ca87f5b6-cd46-40c0-b06d-8ecd57a4373f - Windows Server 2008 R2 B (Standard and Enterprise)
b2ca2689-a9a8-42d7-938d-cf8e9f201958 - Windows Server 2008 R2 C (Datacenter)
8665cb71-468c-4aa3-a337-cb9bc9d5eaac - Windows Server 2012
8456efd3-0c04-4089-8740-5b7238535a65 - Windows Server 2012 R2
6e9fc069-257d-4bc4-b4a7-750514d32743 - Windows Server 2016
8449b1fb-f0ea-497a-99ab-66ca96e9a0f5 - Windows Server 2019
*/

// Get KMS Server Host Build, and CSVLK GroupID and PIDRange
void WINAPI GetKMSHost(KMSBaseRequest* const Request, int *osPkey, int *osHost)
{
	// Initialize Random Seed
	srand(static_cast<unsigned int>(time(nullptr)));

	// Product Specific Detection
	int osTypeIndex = HOST_SERVER2019;
	int keyConfigIndex = PKEYCONFIG_SERVER2019_CSVLK;
	if (Request->AppID == APP_ID_OFFICE14 || Request->AppID == APP_ID_OFFICE15)
	{
		if (Request->KmsID == KMS_ID_OFFICE_2010)
		{
			keyConfigIndex = PKEYCONFIG_OFFICE2010_CSVLK;
			osTypeIndex = rand() % (HOST_SERVER2012R2 + 1 - HOST_SERVER2012) + HOST_SERVER2012;
		}
		else if (Request->KmsID == KMS_ID_OFFICE_2013)
		{
			keyConfigIndex = PKEYCONFIG_OFFICE2013_CSVLK;
			osTypeIndex = rand() % (HOST_SERVER2016 + 1 - HOST_SERVER2012) + HOST_SERVER2012;
		}
		else if (Request->KmsID == KMS_ID_OFFICE_2016)
		{
			keyConfigIndex = PKEYCONFIG_OFFICE2016_CSVLK;
			osTypeIndex = rand() % (HOST_SERVER2019 + 1 - HOST_SERVER2012) + HOST_SERVER2012;
		}
		else if (Request->KmsID == KMS_ID_OFFICE_2019)
		{
			keyConfigIndex = PKEYCONFIG_OFFICE2019_CSVLK;
			osTypeIndex = rand() % (HOST_SERVER2019 + 1 - HOST_SERVER2012R2) + HOST_SERVER2012R2;
		}
	}
	else if (Request->AppID == APP_ID_WINDOWS)
	{
		if
		(
			   Request->KmsID == KMS_ID_WINDOWS_VISTA
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2008A
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2008B
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2008C
		)
		{
			keyConfigIndex = rand() % (PKEYCONFIG_SERVER2019_CSVLK + 1 - PKEYCONFIG_SERVER2012_CSVLK) + PKEYCONFIG_SERVER2012_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_7 
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2008R2A 
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2008R2B 
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2008R2C
		)
		{
			keyConfigIndex = rand() % (PKEYCONFIG_SERVER2019_CSVLK + 1 - PKEYCONFIG_SERVER2012_CSVLK) + PKEYCONFIG_SERVER2012_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_8_VOLUME
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2012
		)
		{
			keyConfigIndex = rand() % (PKEYCONFIG_SERVER2019_CSVLK + 1 - PKEYCONFIG_SERVER2012_CSVLK) + PKEYCONFIG_SERVER2012_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_81_VOLUME 
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2012R2
		)
		{
			keyConfigIndex = rand() % (PKEYCONFIG_SERVER2019_CSVLK + 1 - PKEYCONFIG_SERVER2012R2_CSVLK) + PKEYCONFIG_SERVER2012R2_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_10_VOLUME
			|| Request->KmsID == KMS_ID_WINDOWS_10_UNKNOWN
			|| Request->KmsID == KMS_ID_WINDOWS_10_LTSB_2016
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2016
		)
		{
			keyConfigIndex = rand() % (PKEYCONFIG_SERVER2019_CSVLK + 1 - PKEYCONFIG_SERVER2016_CSVLK) + PKEYCONFIG_SERVER2016_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_10_LTSC_2019
			|| Request->KmsID == KMS_ID_WINDOWS_SERVER_2019
		)
		{
			keyConfigIndex = PKEYCONFIG_SERVER2019_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_8_RETAIL
			|| Request->KmsID == KMS_ID_WINDOWS_81_RETAIL
			|| Request->KmsID == KMS_ID_WINDOWS_10_RETAIL 
		)
		{
			keyConfigIndex = PKEYCONFIG_SERVER2019R_CSVLK;
		}
		else if
		(
			   Request->KmsID == KMS_ID_WINDOWS_10_GOV
		)
		{
			keyConfigIndex = PKEYCONFIG_WIN10GOV_CSVLK;
		}

		if (keyConfigIndex == PKEYCONFIG_SERVER2019_CSVLK || keyConfigIndex == PKEYCONFIG_SERVER2019R_CSVLK)
		{
			osTypeIndex = rand() % (HOST_SERVER2019 + 1 - HOST_SERVER2012R2) + HOST_SERVER2012R2;
		}
		else if (keyConfigIndex == PKEYCONFIG_SERVER2016_CSVLK)
		{
			osTypeIndex = rand() % (HOST_SERVER2016 + 1 - HOST_SERVER2012) + HOST_SERVER2012;
		}
		else if (keyConfigIndex == PKEYCONFIG_SERVER2012R2_CSVLK)
		{
			osTypeIndex = rand() % (HOST_SERVER2012R2 + 1 - HOST_SERVER2012) + HOST_SERVER2012;
		}
		else if (keyConfigIndex == PKEYCONFIG_SERVER2012_CSVLK)
		{
			osTypeIndex = HOST_SERVER2012;
		}
		else if (keyConfigIndex == PKEYCONFIG_WIN10GOV_CSVLK)
		{
			osTypeIndex = HOST_SERVER2019;
		}
	}

	*osPkey = keyConfigIndex;
	*osHost = osTypeIndex;
}

// Generate a random KMS ePID
void WINAPI GenerateRandomKMSPID(WCHAR* const KMSPID, KMSBaseRequest* const Request)
{
	// Random number buffer
	DWORD RandomNumber[4];
	GetRandomBytes((BYTE *)RandomNumber, sizeof(RandomNumber));

	// Choose KMS HostOS and pkeyconfig
	int PkeyIndex = 0;
	int HostIndex = 0;
	GetKMSHost(Request, &PkeyIndex, &HostIndex);
	const KMSHostOS *host = &HostOS[HostIndex];
	const PKEYCONFIG *config = &pkeyconfig[PkeyIndex];

	// Random KeyID
	int RandomID = config->RangeMin + RandomNumber[1] % (config->RangeMax - config->RangeMin);

	// Part 5: License Channel (00=Retail, 01=Retail, 02=OEM, 03=Volume(GVLK,MAK)) - always 03
	DWORD LicenseChannel = 3;

	// Part 6: Language - use system default language
	DWORD LanguageCode = GetSystemDefaultLCID();

	// Minimum value of activation date
	time_t MinDate = host->CsvlkTime;

	// Maximum possible value of activation date
	time_t MaxDate = time(nullptr) - 86400; // limit latest activation date to yesterday

	// Random date between MinDate and MaxDate
	time_t RandomDate = ((ULONG64 *)RandomNumber)[1] & 0x7FFFFFFFFFFFFFFFULL;
	time_t GeneratedDate = MinDate + RandomDate % (MaxDate - MinDate);
	struct tm Date;
	localtime_s(&Date, &GeneratedDate);

	swprintf_s(KMSPID, PID_BUFFER_LEN, L"%05u-%05u-%03u-%06u-%02u-%u-%u.0000-%03d%04d",
		host->Type, config->GroupID, RandomID / 1000000, RandomID % 1000000, LicenseChannel,
		LanguageCode, host->Build, Date.tm_yday + 1, Date.tm_year + 1900
	);
}

#pragma endregion RandomKMSPID

#pragma region KMSPID

// Get user specified PID or Generate random PID according to request and settings
void WINAPI GetKMSPID(WCHAR* const KMSPID, KMSBaseRequest* const Request)
{
	// Assume Windows by default
	int AppIDIndex = APP_INDEX_WINDOWS;
	if (Request->AppID == APP_ID_OFFICE14)
	{
		AppIDIndex = APP_INDEX_OFFICE14;
	}
	if (Request->AppID == APP_ID_OFFICE15)
	{
		if (Request->KmsID == KMS_ID_OFFICE_2013)
		{
			AppIDIndex = APP_INDEX_OFFICE15;
		}
		else if (Request->KmsID == KMS_ID_OFFICE_2016)
		{
			AppIDIndex = APP_INDEX_OFFICE16;
		}
		else if (Request->KmsID == KMS_ID_OFFICE_2019)
		{
			AppIDIndex = APP_INDEX_OFFICE19;
		}
	}

	if (!_wcsicmp(Settings.PIDs[AppIDIndex], RANDOM_PID))
		GenerateRandomKMSPID(KMSPID, Request);
	else
		wcscpy_s(KMSPID, PID_BUFFER_LEN, Settings.PIDs[AppIDIndex]);
}

#pragma endregion KMSPID

#pragma region KMSRegistry

HRESULT WINAPI ReadRegParameter(HKEY hKey, const WCHAR *name, DWORD *dest, DWORD min, DWORD max)
{
	WCHAR buf[256];
	DWORD size = sizeof(buf), type;

	if (RegQueryValueExW(hKey, name, nullptr, &type, (LPBYTE)buf, &size) != ERROR_SUCCESS)
		return S_OK;

	DWORD tempVal;

	if (type == REG_SZ)
	{
		errno = 0;
		tempVal = wcstoul(buf, nullptr, 10);
		if (errno)
			return ERROR_INVALID_PARAMETER;
	}
	else if (type == REG_DWORD)
	{
		tempVal = ((DWORD *)buf)[0];
	}
	else
		return S_OK;

	OutputDebugStringEx(L"[SppExtComObjHook] Found a value %s = %u\n", name, tempVal);

	if (tempVal < min || tempVal > max)
	{
		OutputDebugStringEx(L"[SppExtComObjHook] Invalid setting... ignored\n");
		return ERROR_INVALID_PARAMETER;
	}

	*dest = tempVal;
	return S_OK;
}

HRESULT WINAPI ReadRegParameter(HKEY hKey, const WCHAR *name, QWORD *dest, QWORD min, QWORD max)
{
	WCHAR buf[256];
	DWORD size = sizeof(buf), type;

	if (RegQueryValueExW(hKey, name, nullptr, &type, (LPBYTE)buf, &size) != ERROR_SUCCESS)
		return S_OK;

	if (type != REG_QWORD)
		return S_OK;

	QWORD tempVal;
	tempVal = ((QWORD *)buf)[0];

	OutputDebugStringEx(L"[SppExtComObjHook] Found a value %s = %016I64X\n", name, tempVal);

	if (tempVal < min || tempVal > max)
	{
		OutputDebugStringEx(L"[SppExtComObjHook] Invalid setting... ignored\n");
		return ERROR_INVALID_PARAMETER;
	}

	*dest = tempVal;
	return S_OK;
}

HRESULT WINAPI ReadRegParameter(HKEY hKey, const WCHAR *name, WCHAR *dest, size_t dest_len)
{
	WCHAR buf[256];
	DWORD size = sizeof(buf), type;

	if (RegQueryValueExW(hKey, name, nullptr, &type, (LPBYTE)buf, &size) != ERROR_SUCCESS)
		return S_OK;

	if (type != REG_SZ)
		return S_OK;

	OutputDebugStringEx(L"[SppExtComObjHook] Found a value %s = %s\n", name, buf);

	HRESULT hr = wcscpy_s(dest, dest_len, buf);

#pragma warning(push)
#pragma warning (disable:4390) // C4390: ';' : empty controlled statement found; is this the intent?

	if (hr != S_OK)
	{
		OutputDebugStringEx(L"[SppExtComObjHook] Invalid setting... ignored\n");
	}
#pragma warning (pop)

	return hr;
}

DWORD WINAPI ReadRegistrySettings(void)
{
	HKEY hKey;
	WCHAR KeyName[_MAX_PATH], FileName[_MAX_PATH];

	// Open parameter key
	GetModuleFileNameW(nullptr, FileName, _countof(FileName));
	swprintf_s(KeyName, _countof(KeyName), L"%s\\%s", PARAM_ROOTKEY, wcsrchr(FileName, L'\\') + 1);
	OutputDebugStringEx(L"[SppExtComObjHook] Reading regkey %s ...\n", KeyName);

	// Service parameters not found so just use default settings
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
		return ERROR_SUCCESS;

	// Read KMS Emulation Flag
	ReadRegParameter(hKey, KEY_EMULATION, (DWORD *)&Settings.KMSEnabled, 0, UINT_MAX);
	Settings.KMSEnabled = BOOLIFY(Settings.KMSEnabled);

	// Read ActivationInterval
	ReadRegParameter(hKey, KEY_AI, &Settings.ActivationInterval, 15, 43200);

	// Read RenewalInterval
	ReadRegParameter(hKey, KEY_RI, &Settings.RenewalInterval, 15, 43200);

	// Read KMS HWID
	ReadRegParameter(hKey, KEY_HWID, &Settings.KMSHWID, HWID_MIN, HWID_MAX);

	// Read PIDs
	for (int i = 0; i < APP_INDEX_MAX; i++)
		ReadRegParameter(hKey, AppIDList[i].name, Settings.PIDs[i], PID_BUFFER_LEN);

	RegCloseKey(hKey);

	return ERROR_SUCCESS;
}

#pragma endregion KMSRegistry

#pragma region MIDL_memory_allocator

// Memory allocation function for RPC.
void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
	return HeapAlloc(GetProcessHeap(), 0, len);
}

// Memory deallocation function for RPC.
void __RPC_USER midl_user_free(void __RPC_FAR *ptr)
{
	HeapFree(GetProcessHeap(), 0, ptr);
}

#pragma endregion MIDL_memory_allocator
