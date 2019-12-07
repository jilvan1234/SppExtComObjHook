#pragma once

#include "targetver.h"
#include <Windows.h>
#include <tlhelp32.h>
#include "defines.h"

#pragma comment(linker, "/merge:.pdata=.rdata")
#pragma comment(linker, "/merge:.gfids=.rdata")

// Local prototypes
BOOL WINAPI PauseResumeThreadList(DWORD dwOwnerPID, BOOL bResumeThread);
BOOL WINAPI FindProcessIdByName(LPCTSTR lpPrimaryModuleName, DWORD *lpProcessId);
BOOL WINAPI InjectDll(LPCWSTR lpDllName, DWORD dwProcessId);

void CALLBACK PatcherMain(
	HWND hWnd,
	HINSTANCE hInstance,
	LPWSTR lpCmdLine,
	int nShowCmd)
{
#pragma comment(linker, "/EXPORT:PatcherMainW" "=" __FUNCDNAME__)
	UNREFERENCED_PARAMETER(hWnd);
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(nShowCmd);

	STARTUPINFO si;
	PROCESS_INFORMATION pi = { 0 };
	DWORD dwRet = ERROR_SUCCESS;
	BOOL bRet;

	DWORD SppSvcPid = 0;

	if (nullptr != wcsstr(lpCmdLine, L"SppExtComObj.exe") && FindProcessIdByName(L"sppsvc.exe", &SppSvcPid))
	{
		PauseResumeThreadList(SppSvcPid, FALSE);
		OutputDebugStringEx(L"[SppExtComObjPatcher] Process sppsvc.exe [pid: %u] suspended.\n", SppSvcPid);
	}

	GetStartupInfoW(&si);

	bRet = CreateProcessW(nullptr, lpCmdLine, nullptr, nullptr, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
	if (!bRet)
	{
		dwRet = GetLastError();
		OutputDebugStringEx(L"[SppExtComObjPatcher] CreateProcess failed [cmdLine: %s, error: 0x%08u].\n", lpCmdLine, dwRet);
		goto fail;
	}

	bRet = DebugActiveProcessStop(pi.dwProcessId);
	if (!bRet)
	{
		dwRet = GetLastError();
		OutputDebugStringEx(L"[SppExtComObjPatcher] DebugActiveProcessStop failed [error: 0x%08u].\n", dwRet);
		goto fail;
	}

	OutputDebugStringEx(L"[SppExtComObjPatcher] CreateProcess succeeded [cmdLine: %s, pid: %u, tid: %u].\n", lpCmdLine, pi.dwProcessId, pi.dwThreadId);
	Sleep(100);
	// SuspendThread(pi.hThread);
	InjectDll(DLL_NAME, pi.dwProcessId);

fail:
	ResumeThread(pi.hThread);

	if (SppSvcPid != 0)
	{
		PauseResumeThreadList(SppSvcPid, TRUE);
		OutputDebugStringEx(L"[SppExtComObjPatcher] Process sppsvc.exe [pid: %u] resumed.\n", SppSvcPid);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &dwRet);
	OutputDebugStringEx(L"[SppExtComObjPatcher] Process %s [pid: %u] exited with code %u.\n", lpCmdLine, pi.dwProcessId, dwRet);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	ExitProcess(dwRet);
}

BOOL WINAPI PauseResumeThreadList(DWORD dwOwnerPID, BOOL bResumeThread)
{
	HANDLE hThreadSnap = nullptr;
	BOOL bRet = FALSE;
	THREADENTRY32 te32 = { 0 };

	// Take a snapshot of all threads currently in the system. 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Walk the thread snapshot to find all threads of the process. 
	// If the thread belongs to the process, add its information 
	// to the display list.
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == dwOwnerPID)
			{
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);

				if (bResumeThread)
					ResumeThread(hThread);
				else
					SuspendThread(hThread);

				CloseHandle(hThread);
			}

		} while (Thread32Next(hThreadSnap, &te32));

		bRet = TRUE;
	}

	// Do not forget to clean up the snapshot object. 
	CloseHandle(hThreadSnap);

	return bRet;
}

BOOL WINAPI FindProcessIdByName(LPCWSTR lpPrimaryModuleName, DWORD *lpProcessId)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);

	BOOL bRet = FALSE;

	if (Process32FirstW(hProcessSnap, &pe32))
	{
		do
		{
			if (pe32.szExeFile != nullptr && !_wcsicmp(pe32.szExeFile, lpPrimaryModuleName))
			{
				bRet = TRUE;
				*lpProcessId = pe32.th32ProcessID;
			}

		} while (Process32NextW(hProcessSnap, &pe32));
	}

	CloseHandle(hProcessSnap);

	return bRet;
}

BOOL WINAPI InjectDll(LPCWSTR lpDllName, DWORD dwProcessId)
{
	BOOL bRet = FALSE;

	HANDLE hProcess = nullptr;
	LPVOID addrDllPath = nullptr;

	do
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (nullptr == hProcess)
			break;

		SIZE_T allocSize = (wcslen(lpDllName) + 1) * sizeof(WCHAR);
		addrDllPath = VirtualAllocEx(hProcess, nullptr, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (nullptr == addrDllPath)
			break;

		if (!WriteProcessMemory(hProcess, addrDllPath, lpDllName, allocSize, nullptr))
			break;

		pfnLoadLibraryW addrLoadLibraryW = (pfnLoadLibraryW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
		if (addrLoadLibraryW == nullptr)
			break;

		HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)addrLoadLibraryW, addrDllPath, 0, nullptr);
		if (hThread == nullptr)
			break;

		WaitForSingleObject(hThread, INFINITE);

		// This may be wrong on x64 because LoadLibrary returns HMODULE -> 64-bit
		DWORD dwExitCode;
		GetExitCodeThread(hThread, &dwExitCode);
		CloseHandle(hThread);

		if (dwExitCode != 0)
			bRet = TRUE;

	} while (FALSE);

	if (addrDllPath != nullptr)
		VirtualFreeEx(hProcess, addrDllPath, 0, MEM_RELEASE);
	if (hProcess != nullptr)
		CloseHandle(hProcess);

	return bRet;
}
