#pragma once

#include "targetver.h"
#include <Windows.h>
#include <string.h>
#include <Rpc.h>
#pragma warning(push)
#pragma warning(disable:4091) // C4091: 'typedef ': ignored on left of '' when no variable is declared
#include <imagehlp.h>
#pragma warning(pop)
#include "defines.h"
#include "crypto.h"
#include "kms.h"

// Function prototype
BOOL WINAPI PatchIAT(HMODULE hModule);

// Original function pointers
#define DEFINE_HOOK(module, name) { module, #name, name##_Hook, nullptr } 
#define GET_ORIGINAL_STORE(name) (&APIHooks[name##_Index].original)
#define CALL_ORIGINAL_FUNC(name, ...) (*(pfn##name)(APIHooks[name##_Index].original))(__VA_ARGS__)

typedef enum _APIIndex {
	LoadLibraryW_Index = 0,
	RpcStringBindingComposeW_Index,
	RpcBindingFromStringBindingW_Index,
	RpcStringFreeW_Index,
	RpcBindingFree_Index,
	RpcAsyncInitializeHandle_Index,
	RpcAsyncCompleteCall_Index,
	NdrAsyncClientCall_Index,
	NdrClientCall2_Index,
#ifdef _WIN64
	Ndr64AsyncClientCall_Index,
	NdrClientCall3_Index
#endif
} APIIndex;

APIHook APIHooks[] =
{
	DEFINE_HOOK("kernel32.dll", LoadLibraryW),
	DEFINE_HOOK("rpcrt4.dll", RpcStringBindingComposeW),
	DEFINE_HOOK("rpcrt4.dll", RpcBindingFromStringBindingW),
	DEFINE_HOOK("rpcrt4.dll", RpcStringFreeW),
	DEFINE_HOOK("rpcrt4.dll", RpcBindingFree),
	DEFINE_HOOK("rpcrt4.dll", RpcAsyncInitializeHandle),
	DEFINE_HOOK("rpcrt4.dll", RpcAsyncCompleteCall),
	DEFINE_HOOK("rpcrt4.dll", NdrAsyncClientCall),
	DEFINE_HOOK("rpcrt4.dll", NdrClientCall2),
#ifdef _WIN64
	DEFINE_HOOK("rpcrt4.dll", Ndr64AsyncClientCall),
	DEFINE_HOOK("rpcrt4.dll", NdrClientCall3),
#endif
};

extern KMSServerSettings Settings;

RpcConnection newRpcConnection;

HMODULE WINAPI LoadLibraryW_Hook(LPCWSTR lpFileName)
{
	HMODULE hModule = CALL_ORIGINAL_FUNC(LoadLibraryW, lpFileName);

	if (hModule == nullptr)
	{
		SetLastError(GetLastError());
		return nullptr;
	}

	OutputDebugStringEx(L"[SppExtComObjHook] LoadLibraryW called. [lpFileName: %s, base: 0x%p]\n", lpFileName, hModule);

	WCHAR lpUpCaseFileName[_MAX_PATH];
	wcscpy_s(lpUpCaseFileName, _countof(lpUpCaseFileName), lpFileName);
	_wcsupr_s(lpUpCaseFileName, _countof(lpUpCaseFileName));

	if ( !wcsstr(lpUpCaseFileName, L"OSPPOBJS.DLL") && !wcsstr(lpUpCaseFileName, L"SPPOBJS.DLL") )
	{
		OutputDebugStringEx(L"[SppExtComObjHook] Not a target module. Skipped patching...\n");
		return hModule;
	}

	PatchIAT(hModule);

	return hModule;
}

RPC_STATUS RPC_ENTRY RpcStringBindingComposeW_Hook(WCHAR *ObjUuid, WCHAR *ProtSeq, WCHAR *NetworkAddr, WCHAR *EndPoint, WCHAR *Options, WCHAR **StringBinding)
{
	OutputDebugStringEx(L"[SppExtComObjHook] RpcStringBindingComposeW called [ProtSeq: %s, NetWorkAddr: %s, EndPoint: %s].\n", ProtSeq, NetworkAddr, EndPoint);

	// Check destination address and hook
	if (ProtSeq != nullptr && _wcsicmp(ProtSeq, PROTO_SEQ_TCP) == 0)
	{
		ReadRegistrySettings();

		if (!newRpcConnection.Initialized)
		{
			if (Settings.KMSEnabled)
			{
				OutputDebugStringEx(L"[SppExtComObjHook] Connection Detected... Emulating Server...\n");

				newRpcConnection.Initialized = TRUE;
				newRpcConnection.hThread = GetCurrentThread();
				swprintf_s(newRpcConnection.pszStringBinding, _countof(newRpcConnection.pszStringBinding), L"%s:%s[%s]", ProtSeq, NetworkAddr, EndPoint);
				*StringBinding = newRpcConnection.pszStringBinding;

				return RPC_S_OK;
			}
			else
			{
				// Redirect rpcrt4 call to localhost
				OutputDebugStringEx(L"[SppExtComObjHook] Replaced NetworkAddr from %s to %s\n", NetworkAddr, LOCALHOST_IP);

				newRpcConnection.Initialized = FALSE;

				NetworkAddr = const_cast<wchar_t*>(LOCALHOST_IP);
			}
		}
	}

	// Call original function
	return CALL_ORIGINAL_FUNC(RpcStringBindingComposeW, ObjUuid, ProtSeq, NetworkAddr, EndPoint, Options, StringBinding);
}

RPC_STATUS RPC_ENTRY RpcBindingFromStringBindingW_Hook(WCHAR *StringBinding, RPC_BINDING_HANDLE *Binding)
{
	if (StringBinding != nullptr && Binding != nullptr)
	{
		if (newRpcConnection.Initialized && newRpcConnection.pAsync == nullptr)
		{
			if (newRpcConnection.hThread == GetCurrentThread() && !_wcsicmp(StringBinding, newRpcConnection.pszStringBinding))
			{
				OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Return fake binding...\n");

				GetRandomBytes((BYTE *)&newRpcConnection.hRpcBinding, sizeof(newRpcConnection.hRpcBinding));
				*Binding = newRpcConnection.hRpcBinding;

				OutputDebugStringEx(L"[SppExtComObjHook] RpcBindingFromStringBindingW called [StringBinding: %s, Binding: 0x%p @ 0x%p].\n", StringBinding, *Binding, Binding);

				return RPC_S_OK;
			}
		}
	}

	RPC_STATUS ret = CALL_ORIGINAL_FUNC(RpcBindingFromStringBindingW, StringBinding, Binding);

	OutputDebugStringEx(L"[SppExtComObjHook] RpcBindingFromStringBindingW called [StringBinding: %s, Binding: 0x%p @ 0x%p].\n", StringBinding, *Binding, Binding);

	return ret;
}

RPC_STATUS RPC_ENTRY RpcStringFreeW_Hook(WCHAR **String)
{
	if (newRpcConnection.Initialized && String != nullptr)
	{
		if (newRpcConnection.hThread == GetCurrentThread() && !_wcsicmp(*String, newRpcConnection.pszStringBinding))
		{
			OutputDebugStringEx(L"[SppExtComObjHook] Free StringBinding...\n");

			memset(newRpcConnection.pszStringBinding, 0, sizeof(newRpcConnection.pszStringBinding));
			*String = nullptr;

			return RPC_S_OK;
		}
	}

	return CALL_ORIGINAL_FUNC(RpcStringFreeW, String);
}

RPC_STATUS RPC_ENTRY RpcBindingFree_Hook(RPC_BINDING_HANDLE *Binding)
{
	if (newRpcConnection.Initialized && Binding != nullptr)
	{
		if (*Binding == newRpcConnection.hRpcBinding && newRpcConnection.hThread == GetCurrentThread())
		{
			OutputDebugStringEx(L"[SppExtComObjHook] Free Connection...\n");

			newRpcConnection.Initialized = FALSE;
			newRpcConnection.hRpcBinding = nullptr;
			newRpcConnection.pAsync = nullptr;
			newRpcConnection.hThread = nullptr;

			return RPC_S_OK;
		}
	}

	return CALL_ORIGINAL_FUNC(RpcBindingFree, Binding);
}

RPC_STATUS RPC_ENTRY RpcAsyncInitializeHandle_Hook(PRPC_ASYNC_STATE pAsync, unsigned int Size)
{
	RPC_STATUS status = CALL_ORIGINAL_FUNC(RpcAsyncInitializeHandle, pAsync, Size);

	if (status != RPC_S_OK)
		return status;

	if (newRpcConnection.Initialized && newRpcConnection.hRpcBinding != nullptr && newRpcConnection.pAsync == nullptr)
	{
		if (newRpcConnection.hThread == GetCurrentThread())
		{
			OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Saved Async Handle\n");
			newRpcConnection.pAsync = pAsync;
		}
	}

	return status;
}

RPC_STATUS RPC_ENTRY RpcAsyncCompleteCall_Hook(PRPC_ASYNC_STATE pAsync, PVOID Reply)
{
	if (pAsync != nullptr && Reply != nullptr)
	{
		if (newRpcConnection.Initialized && newRpcConnection.pAsync != nullptr && newRpcConnection.hRpcBinding != nullptr)
		{
			if (newRpcConnection.hThread == GetCurrentThread() && pAsync == newRpcConnection.pAsync)
			{
				OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Return RPC_S_OK...\n");

				return RPC_S_OK;
			}
		}
	}

	return CALL_ORIGINAL_FUNC(RpcAsyncCompleteCall, pAsync, Reply);
}

CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrAsyncClientCall_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...)
{
	OutputDebugStringEx(L"[SppExtComObjHook] NdrAsyncClientCall called\n");

#ifdef _WIN64
	va_list ap = nullptr;
	va_start(ap, pFormat);
	PRPC_ASYNC_STATE pAsync = (PRPC_ASYNC_STATE)va_arg(ap, PVOID);
	RPC_BINDING_HANDLE Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	int requestSize = (int)va_arg(ap, int);
	BYTE *requestData = (BYTE *)va_arg(ap, PVOID);
	int *responseSize = (int *)va_arg(ap, PVOID);
	BYTE **responseData = (BYTE **)va_arg(ap, PVOID);
	va_end(ap);
#else
	DWORD* funcVarList = *(DWORD**)(((BYTE*)&pFormat) + sizeof(const unsigned char*));
	PRPC_ASYNC_STATE pAsync = (PRPC_ASYNC_STATE)(funcVarList[0]);
	RPC_BINDING_HANDLE Binding = (RPC_BINDING_HANDLE)(funcVarList[1]);
	int requestSize = (int)(funcVarList[2]);
	BYTE* requestData = (BYTE*)(funcVarList[3]);
	int* responseSize = (int*)(funcVarList[4]);
	BYTE** responseData = (BYTE**)(funcVarList[5]);
#endif

	OutputDebugStringEx(L"[SppExtComObjHook] pStubDescriptor = 0x%p, pFormat = 0x%p, pAsync = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pStubDescriptor, pFormat, pAsync, Binding, requestSize, requestData, responseSize, responseData);

	if (newRpcConnection.Initialized && pStubDescriptor != nullptr && pFormat != nullptr)
	{
		if (newRpcConnection.hRpcBinding == Binding && newRpcConnection.pAsync == pAsync)
		{
			if (newRpcConnection.hThread == GetCurrentThread())
			{
				if (pAsync->u.APC.NotificationRoutine != nullptr && pAsync->u.APC.NotificationRoutine != INVALID_HANDLE_VALUE)
				{
					ReadRegistrySettings();

					OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Writing Response!\n");

					if (ActivationResponse(requestSize, requestData, responseSize, responseData) == RPC_S_OK)
					{
						OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Success!\n");
					}
					else
					{
						OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Failed!\n");
					}

					SetEvent(pAsync->u.APC.NotificationRoutine);

					CLIENT_CALL_RETURN ret = { 0 };

					return ret;
				}
			}
		}
	}

#ifdef _WIN64
	return CALL_ORIGINAL_FUNC(NdrAsyncClientCall, pStubDescriptor, pFormat, pAsync, Binding, requestSize, requestData, responseSize, responseData);
#else
	return CALL_ORIGINAL_FUNC(NdrAsyncClientCall, pStubDescriptor, pFormat, funcVarList);
#endif
}

CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall2_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...)
{
	OutputDebugStringEx(L"[SppExtComObjHook] NdrClientCall2 called\n");

#ifdef _WIN64
	va_list ap = nullptr;
	va_start(ap, pFormat);
	RPC_BINDING_HANDLE Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	int requestSize = (int)va_arg(ap, int);
	BYTE *requestData = (BYTE *)va_arg(ap, PVOID);
	int *responseSize = (int *)va_arg(ap, PVOID);
	BYTE **responseData = (BYTE **)va_arg(ap, PVOID);
	va_end(ap);
#else
	DWORD* funcVarList = *(DWORD**)(((BYTE*)&pFormat) + sizeof(const unsigned char*));
	RPC_BINDING_HANDLE Binding = (RPC_BINDING_HANDLE)(funcVarList[0]);
	int requestSize = (int)(funcVarList[1]);
	BYTE* requestData = (BYTE*)(funcVarList[2]);
	int* responseSize = (int*)(funcVarList[3]);
	BYTE** responseData = (BYTE**)(funcVarList[4]);
#endif

	OutputDebugStringEx(L"[SppExtComObjHook] pStubDescriptor = 0x%p, pFormat = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pStubDescriptor, pFormat, Binding, requestSize, requestData, responseSize, responseData);

	if (newRpcConnection.Initialized && pStubDescriptor != nullptr && pFormat != nullptr)
	{
		if (newRpcConnection.hRpcBinding == Binding)
		{
			if (newRpcConnection.hThread == GetCurrentThread())
			{
				ReadRegistrySettings();

				OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Writing Response!\n");

				if (ActivationResponse(requestSize, requestData, responseSize, responseData) == RPC_S_OK)
				{
					OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Success!\n");
				}
				else
				{
					OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Failed!\n");
				}

				CLIENT_CALL_RETURN ret = { 0 };

				return ret;
			}
		}
	}

#ifdef _WIN64
	return CALL_ORIGINAL_FUNC(NdrClientCall2, pStubDescriptor, pFormat, Binding, requestSize, requestData, responseSize, responseData);
#else
	return CALL_ORIGINAL_FUNC(NdrClientCall2, pStubDescriptor, pFormat, funcVarList);
#endif
}

#ifdef _WIN64
CLIENT_CALL_RETURN RPC_VAR_ENTRY Ndr64AsyncClientCall_Hook(MIDL_STUBLESS_PROXY_INFO *pProxyInfo, unsigned long nProcNum, void *pReturnValue, ...)
{
	OutputDebugStringEx(L"[SppExtComObjHook] Ndr64AsyncClientCall called\n");

	va_list ap = nullptr;
	va_start(ap, pReturnValue);
	PRPC_ASYNC_STATE pAsync = (PRPC_ASYNC_STATE)va_arg(ap, PVOID);
	RPC_BINDING_HANDLE Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	int requestSize = va_arg(ap, int);
	BYTE *requestData = va_arg(ap, BYTE *);
	int *responseSize = va_arg(ap, int *);
	BYTE **responseData = va_arg(ap, BYTE **);
	va_end(ap);

	OutputDebugStringEx(L"[SppExtComObjHook] pProxyInfo = 0x%p, nProcNum = %u, pReturnValue = 0x%p, pAsync = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pProxyInfo, nProcNum, pReturnValue, pAsync, Binding, requestSize, requestData, responseSize, responseData);

	if (newRpcConnection.Initialized && pProxyInfo != nullptr)
	{
		if (newRpcConnection.hRpcBinding == Binding && newRpcConnection.pAsync == pAsync)
		{
			if (newRpcConnection.hThread == GetCurrentThread())
			{
				if (pAsync->u.APC.NotificationRoutine != nullptr && pAsync->u.APC.NotificationRoutine != INVALID_HANDLE_VALUE)
				{
					ReadRegistrySettings();

					OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Writing Response!\n");

					if (ActivationResponse(requestSize, requestData, responseSize, responseData) == RPC_S_OK)
					{
						OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Success!\n");
					}
					else
					{
						OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Failed!\n");
					}

					SetEvent((HANDLE)(pAsync->u.APC.NotificationRoutine));

					CLIENT_CALL_RETURN ret = { 0 };

					return ret;
				}
			}
		}
	}

	return CALL_ORIGINAL_FUNC(Ndr64AsyncClientCall, pProxyInfo, nProcNum, pReturnValue, pAsync, Binding, requestSize, requestData, responseSize, responseData);
}

CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall3_Hook(MIDL_STUBLESS_PROXY_INFO *pProxyInfo, unsigned long nProcNum, void *pReturnValue, ...)
{
	OutputDebugStringEx(L"[SppExtComObjHook] NdrClientCall3 called\n");

	va_list ap = nullptr;
	va_start(ap, pReturnValue);
	RPC_BINDING_HANDLE Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	int requestSize = va_arg(ap, int);
	BYTE *requestData = va_arg(ap, BYTE *);
	int *responseSize = va_arg(ap, int *);
	BYTE **responseData = va_arg(ap, BYTE **);
	va_end(ap);

	OutputDebugStringEx(L"[SppExtComObjHook] pProxyInfo = 0x%p, nProcNum = %u, pReturnValue = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pProxyInfo, nProcNum, pReturnValue, Binding, requestSize, requestData, responseSize, responseData);

	if (newRpcConnection.Initialized && pProxyInfo != nullptr)
	{
		if (newRpcConnection.hRpcBinding == Binding)
		{
			if (newRpcConnection.hThread == GetCurrentThread())
			{
				ReadRegistrySettings();

				OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Writing Response!\n");

				if (ActivationResponse(requestSize, requestData, responseSize, responseData) == RPC_S_OK)
				{
					OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Success!\n");
				}
				else
				{
					OutputDebugStringEx(L"[SppExtComObjHook] Emulating Server... Activation Failed!\n");
				}

				CLIENT_CALL_RETURN ret = { 0 };

				return ret;
			}
		}
	}

	return CALL_ORIGINAL_FUNC(NdrClientCall3, pProxyInfo, nProcNum, pReturnValue, Binding, requestSize, requestData, responseSize, responseData);
}
#endif

PIMAGE_IMPORT_DESCRIPTOR WINAPI GetImportDescriptor(HMODULE hModule)
{
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_DATA_DIRECTORY pDirectory;
	ULONG_PTR Address;
	LPBYTE pb = (LPBYTE)hModule;

	if (((WORD *)pb)[0] != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pNtHeaders = (PIMAGE_NT_HEADERS)(pb + pDosHeader->e_lfanew);

	if (((DWORD *)pNtHeaders)[0] != IMAGE_NT_SIGNATURE)
		return nullptr;

	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	Address = pDirectory->VirtualAddress;

	if (Address == 0)
		return nullptr;

	return (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)hModule + Address);
}

// Create RpcStringBindingComposeW and GetProcAddressHook hooks
BOOL WINAPI PatchIATInternal(HMODULE hModule, APIHook* APIHookInfo)
{
	// Get original function addresses being hooked
	FARPROC Original = GetProcAddress(GetModuleHandleA(APIHookInfo->module), APIHookInfo->name);
	if (Original == nullptr)
		return FALSE;

	// Hold original address
	if (APIHookInfo->original == nullptr)
		APIHookInfo->original = Original;

	// Get base address of our process primary module
	ULONG_PTR BaseAddress = (ULONG_PTR)hModule;

	// Get import table
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = GetImportDescriptor(hModule);

	if (pImageImportDescriptor == nullptr)
		return FALSE;

	// Search through import table
	for (; pImageImportDescriptor->Name; pImageImportDescriptor++)
	{

		LPCSTR lpDllName = (LPCSTR)(BaseAddress + pImageImportDescriptor->Name);

		if (_stricmp(lpDllName, APIHookInfo->module))
			continue;

		PIMAGE_THUNK_DATA pImageThunkData = (PIMAGE_THUNK_DATA)(BaseAddress + pImageImportDescriptor->FirstThunk);
		PIMAGE_THUNK_DATA pOrgImageThunkData = (PIMAGE_THUNK_DATA)(BaseAddress + pImageImportDescriptor->OriginalFirstThunk);

		for (; pImageThunkData->u1.Function; pImageThunkData++, pOrgImageThunkData++)
		{
			FARPROC pfnImportedFunc = (FARPROC)(pImageThunkData->u1.Function);

			// Patch
			if (pfnImportedFunc == Original)
			{
				OutputDebugStringEx(L"[SppExtComObjHook] Replaced %S import 0x%p @ 0x%p with hook entry 0x%p in base 0x%p.\n",
					APIHookInfo->name, (void*)pImageThunkData->u1.Function, (void*)(&pImageThunkData->u1.Function), APIHookInfo->hook, hModule);
				DWORD flOldProtect;
				VirtualProtect(pImageThunkData, sizeof(ULONG_PTR), PAGE_READWRITE, &flOldProtect);
				WriteProcessMemory(GetCurrentProcess(), pImageThunkData, &APIHookInfo->hook, sizeof(ULONG_PTR), nullptr);
				VirtualProtect(pImageThunkData, sizeof(ULONG_PTR), flOldProtect, &flOldProtect);
			}
		}
	}

	return TRUE;
}

BOOL WINAPI PatchIAT(HMODULE hModule)
{
	BOOL bRet = TRUE;

	for (int i = 0; i < _countof(APIHooks); i++)
	{
		if (!PatchIATInternal(hModule, &APIHooks[i]))
		{
			bRet = FALSE;
			break;
		}
	}

	return bRet;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD fdwReason,
	_In_ LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	OutputDebugStringEx(L"[SppExtComObjHook] DllMain entry. [nReason: %u]\n", fdwReason);

	BOOL bRet = TRUE;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		bRet = DisableThreadLibraryCalls(hinstDLL) && PatchIAT(GetModuleHandleA(nullptr));
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return bRet;
}
