#pragma once

#include "targetver.h"
#include <Windows.h>
#include <Rpc.h>
#include <stdio.h>
#include <stdlib.h>

// Main dll filename
#define DLL_NAME L"SppExtComObjHook.dll"

// Fake KMS host IP address
#define LOCALHOST_IP L"127.0.0.1"
#define PROTO_SEQ_TCP L"ncacn_ip_tcp"

// Function typedef
typedef HMODULE (WINAPI *pfnLoadLibraryW)(LPCWSTR lpFileName);
typedef RPC_STATUS (RPC_ENTRY *pfnRpcStringBindingComposeW)(WCHAR *ObjUuid, WCHAR *ProtSeq, WCHAR *NetworkAddr, WCHAR *EndPoint, WCHAR *Options, WCHAR **StringBinding);
typedef RPC_STATUS (RPC_ENTRY *pfnRpcBindingFromStringBindingW)(WCHAR *StringBinding, RPC_BINDING_HANDLE *Binding);
typedef RPC_STATUS (RPC_ENTRY *pfnRpcStringFreeW)(WCHAR **String);
typedef RPC_STATUS (RPC_ENTRY *pfnRpcBindingFree)(RPC_BINDING_HANDLE *Binding);
typedef RPC_STATUS (RPC_ENTRY *pfnRpcAsyncInitializeHandle)(PRPC_ASYNC_STATE pAsync, unsigned int Size);
typedef RPC_STATUS (RPC_ENTRY *pfnRpcAsyncCompleteCall)(PRPC_ASYNC_STATE pAsync, PVOID Reply);
typedef CLIENT_CALL_RETURN (RPC_VAR_ENTRY *pfnNdrAsyncClientCall)(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);
typedef CLIENT_CALL_RETURN (RPC_VAR_ENTRY *pfnNdrClientCall2)(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);
#ifdef _WIN64
typedef CLIENT_CALL_RETURN (RPC_VAR_ENTRY *pfnNdr64AsyncClientCall)(MIDL_STUBLESS_PROXY_INFO *pProxyInfo, unsigned long nProcNum, void *pReturnValue, ...);
typedef CLIENT_CALL_RETURN (RPC_VAR_ENTRY *pfnNdrClientCall3)(MIDL_STUBLESS_PROXY_INFO *pProxyInfo, unsigned long nProcNum, void *pReturnValue, ...);
#endif

// Hook functions prototype
HMODULE WINAPI LoadLibraryW_Hook(LPCWSTR lpFileName);
RPC_STATUS RPC_ENTRY RpcStringBindingComposeW_Hook(WCHAR *ObjUuid, WCHAR *ProtSeq, WCHAR *NetworkAddr, WCHAR *EndPoint, WCHAR *Options, WCHAR **StringBinding);
RPC_STATUS RPC_ENTRY RpcBindingFromStringBindingW_Hook(WCHAR *StringBinding, RPC_BINDING_HANDLE *Binding);
RPC_STATUS RPC_ENTRY RpcStringFreeW_Hook(WCHAR **String);
RPC_STATUS RPC_ENTRY RpcBindingFree_Hook(RPC_BINDING_HANDLE *Binding);
RPC_STATUS RPC_ENTRY RpcAsyncInitializeHandle_Hook(PRPC_ASYNC_STATE pAsync, unsigned int Size);
RPC_STATUS RPC_ENTRY RpcAsyncCompleteCall_Hook(PRPC_ASYNC_STATE pAsync, PVOID Reply);
CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrAsyncClientCall_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);
CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall2_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);
#ifdef _WIN64
CLIENT_CALL_RETURN RPC_VAR_ENTRY Ndr64AsyncClientCall_Hook(MIDL_STUBLESS_PROXY_INFO *pProxyInfo, unsigned long nProcNum, void *pReturnValue, ...);
CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall3_Hook(MIDL_STUBLESS_PROXY_INFO *pProxyInfo, unsigned long nProcNum, void *pReturnValue, ...);
#endif

typedef struct _APIHook {
	const char *module;
	const char *name;
	LPVOID hook;
	LPVOID original;
} APIHook;

typedef struct _RpcConnection {
	BOOL Initialized;
	WCHAR pszStringBinding[128];
	PVOID hRpcBinding;
	PVOID pAsync;
	HANDLE hThread;
	PBYTE responseData;
} RpcConnection, *PRpcConnection;

#ifdef _DEBUG
#   define OutputDebugStringEx( str, ... ) \
      { \
        WCHAR c[512]; \
        swprintf_s( c, _countof(c), str, __VA_ARGS__ ); \
        OutputDebugStringW( c ); \
      }
#else
#    define OutputDebugStringEx( str, ... )
#endif
