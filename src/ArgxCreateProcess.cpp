/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

#include "ArgX.h"
#include "PEB.hpp"

#define ARGX_MAXIMUM_FLAT_LENGTH 32767

namespace {

  HMODULE hNtDll = NULL;
  HMODULE hKernel32Dll = NULL;

  HANDLE hProcessHeap = NULL;

  // PROCESS_BASIC_INFORMATION, but always 64-bit
  typedef struct _PROCESS_BASIC_INFORMATION64 {
    DWORD64 Reserved1;
    DWORD64 PebBaseAddress;
    DWORD64 Reserved2[2];
    DWORD64 UniqueProcessId;
    DWORD64 Reserved3;
  } PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

  typedef void (__stdcall *LPFN_GETSYSTEMINFO)(LPSYSTEM_INFO);
  typedef NTSTATUS (NTAPI *LPFN_NTQUERYINFOPROCESS)(HANDLE, PROCESSINFOCLASS,
						    PVOID, ULONG, PULONG);
  typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

  LPFN_GETSYSTEMINFO fnGetSystemInfo;
  LPFN_ISWOW64PROCESS fnIsWow64Process;
  LPFN_NTQUERYINFOPROCESS fnNtQueryInformationProcess;

#ifndef _WIN64
  typedef NTSTATUS (NTAPI *LPFN_NTWOW64READMEM64)(HANDLE, ULONG64, PVOID,
						  ULONG64, PULONG64);
  typedef NTSTATUS (NTAPI *LPFN_NTWOW64WRITEMEM64)(HANDLE, ULONG64, LPCVOID,
						   ULONG64, PULONG64);
  typedef NTSTATUS (NTAPI *LPFN_NTWOW64ALLOCMEM64)(HANDLE, PULONG64, ULONG64,
						   PULONG64, ULONG, ULONG);

  LPFN_NTWOW64READMEM64 fnNtWow64ReadVirtualMemory64;
  LPFN_NTWOW64WRITEMEM64 fnNtWow64WriteVirtualMemory64;
  LPFN_NTWOW64ALLOCMEM64 fnNtWow64AllocateVirtualMemory64;
#endif

  typedef BOOL (__stdcall *LPFN_ARGXCREATEPROCESSW)(LPCWSTR, LPCWSTR*, DWORD,
						    LPSECURITY_ATTRIBUTES,
						    LPSECURITY_ATTRIBUTES, BOOL,
						    DWORD, LPVOID, LPCWSTR,
						    LPSTARTUPINFOW,
						    LPPROCESS_INFORMATION);

  LPFN_ARGXCREATEPROCESSW fnArgxCreateProcessW;

  LPWSTR PackArgv(LPCWSTR* lpArgv, DWORD dwArgc);

  typedef enum {
    BITNESS_WOW64 = 0x1000,

    BITNESS_32_BIT = 32,
    BITNESS_32_BIT_WOW64 = (BITNESS_32_BIT|BITNESS_WOW64),
    BITNESS_64_BIT = 64
  } BITNESS, *PBITNESS;

  BOOL GetProcessBitness(HANDLE hProcess, BITNESS* bitness);

  BOOL CALLBACK InitArgxCreateFunction(PINIT_ONCE InitOnce, PVOID Parameter,
				       PVOID *lpContext);

  BOOL GetImageBaseAddress(HANDLE hProcess,
			   BITNESS bitness,
			   DWORD64* pImageBaseAddr);

  BOOL FindArgXSection32(HANDLE hProcess,
			 DWORD64 imageBaseAddr,
			 DWORD64* pArgXSectionAddr);
  BOOL FindArgXSection64(HANDLE hProcess,
			 DWORD64 imageBaseAddr,
			 DWORD64* pArgXSectionAddr);

  BOOL WriteArguments32(HANDLE hProcess,
			DWORD64 pArgXSectionAddr,
			LPCWSTR* lpArgv,
			DWORD dwArgc);
  BOOL WriteArguments64(HANDLE hProcess,
			DWORD64 pArgXSectionAddr,
			LPCWSTR* lpArgv,
			DWORD dwArgc);

  BOOL ArgxReadProcessMemory(HANDLE hProcess, DWORD64 addr, LPVOID pData, SIZE_T len, SIZE_T* bytesRead);
  BOOL ArgxWriteProcessMemory(HANDLE hProcess, DWORD64 addr, LPCVOID pData, SIZE_T len, SIZE_T* bytesWritten);
  DWORD64 ArgxVirtualAllocEx(HANDLE hProcess, DWORD64 addr, SIZE_T len, DWORD flAllicationType, DWORD flProtect);

  INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

  PVOID Allocate(SIZE_T length) {
    return HeapAlloc(hProcessHeap, 0, length);
  }

  void Free(PVOID ptr) {
    if (ptr)
      HeapFree(hProcessHeap, 0, ptr);
  }

  // Using this avoids bringing in the C runtime just for memcmp(); we only
  // compare 4 or 8 bytes anyway, so the compiler should be able to optimise
  // this.
  BOOL EqualMemory(const void* pa, const void* pb, SIZE_T len) {
    const char *pca = (const char *)pa;
    const char *pcb = (const char *)pb;
    const char *pend = pca + len;

    while (pca != pend) {
      if (*pca++ != *pcb++)
	return FALSE;
    }

    return TRUE;
  }
}

BOOL ARGXAPI
ArgxCreateProcessW(LPCWSTR			lpApplicationName,
		   LPCWSTR*			lpArgv,
		   DWORD			dwArgc,
		   LPSECURITY_ATTRIBUTES	lpProcessAttributes,
		   LPSECURITY_ATTRIBUTES	lpThreadAttributes,
		   BOOL				bInheritHandles,
		   DWORD			dwCreationFlags,
		   LPVOID			lpEnvironment,
		   LPCWSTR			lpCurrentDirectory,
		   LPSTARTUPINFOW		lpStartupInfo,
		   LPPROCESS_INFORMATION	lpProcessInformation)
{
  // Make sure we have our function pointers
  if (!InitOnceExecuteOnce(&initOnce,
			   InitArgxCreateFunction,
			   NULL,
			   NULL))
    return FALSE;

  // If kernel32 implements this function, call that implementation instead;
  // this is to allow Microsoft to take over implementation of ArgxCreateProcessW
  // in some future version of Windows.
  if (fnArgxCreateProcessW) {
    return fnArgxCreateProcessW(lpApplicationName,
				lpArgv,
				dwArgc,
				lpProcessAttributes,
				lpThreadAttributes,
				bInheritHandles,
				dwCreationFlags,
				lpEnvironment,
				lpCurrentDirectory,
				lpStartupInfo,
				lpProcessInformation);
  }

  // We also insist on having a valid argv pointer and a non-zero argc
  if (!lpArgv || !dwArgc) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  // Build a flat command line string
  LPWSTR pszCmdline = PackArgv(lpArgv, dwArgc);

  // Actually create the process
  BOOL result = CreateProcessW(lpApplicationName,
			       pszCmdline,
			       lpProcessAttributes,
			       lpThreadAttributes,
			       bInheritHandles,
			       dwCreationFlags | CREATE_SUSPENDED,
			       lpEnvironment,
			       lpCurrentDirectory,
			       lpStartupInfo,
			       lpProcessInformation);

  if (!result) {
    Free(pszCmdline);
    return FALSE;
  }

  Free(pszCmdline);

  // Find its image base address and bitness
  BITNESS bitness;
  DWORD64 imageBaseAddr;

  if (!GetProcessBitness(lpProcessInformation->hProcess, &bitness))
    goto fail;

  if (!GetImageBaseAddress(lpProcessInformation->hProcess,
			   bitness,
			   &imageBaseAddr))
    goto fail;

  // Look for the ArgX section
  BOOL bSupportsArgX = FALSE;
  DWORD64 ulArgXSectionAddr = 0;

  switch (bitness) {
  case BITNESS_32_BIT:
  case BITNESS_32_BIT_WOW64:
    bSupportsArgX = FindArgXSection32(lpProcessInformation->hProcess,
				      imageBaseAddr,
				      &ulArgXSectionAddr);
    break;
  case BITNESS_64_BIT:
    bSupportsArgX = FindArgXSection64(lpProcessInformation->hProcess,
				      imageBaseAddr,
				      &ulArgXSectionAddr);
    break;
  }

  if (bSupportsArgX) {
    // Write the argument vector and update the ArgX section
    BOOL bRet = FALSE;

    switch (bitness) {
    case BITNESS_32_BIT:
    case BITNESS_32_BIT_WOW64:
      bRet = WriteArguments32(lpProcessInformation->hProcess,
			      ulArgXSectionAddr,
			      lpArgv,
			      dwArgc);
      break;
    case BITNESS_64_BIT:
      bRet = WriteArguments64(lpProcessInformation->hProcess,
			      ulArgXSectionAddr,
			      lpArgv,
			      dwArgc);
      break;
    }

    if (!bRet)
      goto fail;
  }

  // Start the process if we were supposed to
  if (!(dwCreationFlags & CREATE_SUSPENDED)) {
    if (!ResumeThread(lpProcessInformation->hThread))
      goto fail;
  }

  return TRUE;

 fail:
  {
    DWORD dwErr = GetLastError();
    TerminateProcess(lpProcessInformation->hProcess, 0);
    CloseHandle(lpProcessInformation->hProcess);
    CloseHandle(lpProcessInformation->hThread);
    SetLastError(dwErr);
  }
  return FALSE;
}

namespace {

BOOL CALLBACK InitArgxCreateFunction(PINIT_ONCE, PVOID, PVOID *)
{
  hProcessHeap = GetProcessHeap();
  if (!hProcessHeap)
    return FALSE;

  hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtDll)
    return FALSE;

  hKernel32Dll = GetModuleHandleW(L"kernel32.dll");
  if (!hKernel32Dll)
    return FALSE;

  // Look for the function in kernel32, so that Microsoft can override this
  // implementation
  fnArgxCreateProcessW = reinterpret_cast<LPFN_ARGXCREATEPROCESSW>(GetProcAddress(hKernel32Dll, "ArgxCreateProcessW"));

  // Look up various low-level functions we need
  fnIsWow64Process = reinterpret_cast<LPFN_ISWOW64PROCESS>(GetProcAddress(hKernel32Dll, "IsWow64Process"));
  fnGetSystemInfo = reinterpret_cast<LPFN_GETSYSTEMINFO>(GetProcAddress(hKernel32Dll, "GetNativeSystemInfo"));
  if (!fnGetSystemInfo)
    fnGetSystemInfo = reinterpret_cast<LPFN_GETSYSTEMINFO>(GetProcAddress(hKernel32Dll, "GetSystemInfo"));
  fnNtQueryInformationProcess = reinterpret_cast<LPFN_NTQUERYINFOPROCESS>(GetProcAddress(hNtDll, "NtQueryInformationProcess"));

#ifndef _WIN64
  // Get some Wow64 pointers, if this is a Wow64 process
  LPFN_NTQUERYINFOPROCESS fnWowQueryInfoProcess;
  fnWowQueryInfoProcess = reinterpret_cast<LPFN_NTQUERYINFOPROCESS>(GetProcAddress(hNtDll, "NtWow64QueryInformationProcess64"));

  if (fnWowQueryInfoProcess)
    fnNtQueryInformationProcess = fnWowQueryInfoProcess;

  fnNtWow64ReadVirtualMemory64 = reinterpret_cast<LPFN_NTWOW64READMEM64>(GetProcAddress(hNtDll, "NtWow64ReadVirtualMemory64"));
  fnNtWow64WriteVirtualMemory64 = reinterpret_cast<LPFN_NTWOW64WRITEMEM64>(GetProcAddress(hNtDll, "NtWow64WriteVirtualMemory64"));
  fnNtWow64AllocateVirtualMemory64 = reinterpret_cast<LPFN_NTWOW64ALLOCMEM64>(GetProcAddress(hNtDll, "NtWow64AllocateVirtualMemory64"));
#endif

  return TRUE;
}

LPWSTR
PackArgv(LPCWSTR* lpArgv, DWORD dwArgc)
{
  DWORD dwLen = 6;

  /* We do this in two passes; the first works out how long the result will
     be; the second actually fills it in */
  for (DWORD dwArg = 0; dwArg < dwArgc; ++dwArg) {
    LPCWSTR szArg = lpArgv[dwArg];

    const WCHAR *ptr = szArg;
    DWORD dwSlashCount = 0;
    BOOL quoted = FALSE;
    while (*ptr) {
      WCHAR ch = *ptr++;

      switch (ch) {
      case '\\':
	++dwSlashCount;
	break;
      case '"':
	if (dwSlashCount)
	  dwLen += dwSlashCount * 2;
	dwLen += 2;
	dwSlashCount = 0;
	break;
      case ' ':
      case '\t':
	if (!quoted) {
	  quoted = TRUE;
	  dwLen += 2;
	}
      default:
	if (dwSlashCount) {
	  dwLen += dwSlashCount;
	  dwSlashCount = 0;
	}
	++dwLen;
      }
    }

    if (dwSlashCount) {
      if (quoted)
	dwLen += dwSlashCount * 2 + 1;
      else
	dwLen += dwSlashCount;
    }
  }

  // Spaces and NULL
  dwLen += dwArgc;

  if (dwLen >= ARGX_MAXIMUM_FLAT_LENGTH)
    return NULL;

  LPWSTR result = (LPWSTR)Allocate(dwLen * sizeof(WCHAR));
  WCHAR *ptr = result;

  for (DWORD dwArg = 0; dwArg < dwArgc; ++dwArg) {
    LPCWSTR szArg = lpArgv[dwArg];
    const WCHAR *pt2 = szArg;
    DWORD dwSlashCount = 0;
    BOOL quoted = FALSE;

    if (dwArg)
      *ptr++ = ' ';

    while (*pt2) {
      WCHAR ch = *pt2++;
      if (ch == ' ' || ch == '\t') {
	quoted = TRUE;
	break;
      }
    }

    if (quoted)
      *ptr++ = '"';

    pt2 = szArg;
    while (*pt2) {
      WCHAR ch = *pt2++;

      switch (ch) {
      case '\\':
	++dwSlashCount;
	break;
      case '"':
	{
	  WCHAR *pend = ptr + 2 * dwSlashCount;
	  while (ptr < pend)
	    *ptr++ = '\\';
	  dwSlashCount = 0;
	  *ptr++ = '\\';
	  *ptr++ = '"';
	}
	break;
      default:
	{
	  WCHAR *pend = ptr + dwSlashCount;
	  while (ptr < pend)
	    *ptr++ = '\\';
	  dwSlashCount = 0;
	  *ptr++ = ch;
	}
	break;
      }
    }

    if (dwSlashCount) {
      if (quoted) {
	WCHAR *pend = ptr + 2 * dwSlashCount;
	while (ptr < pend)
	  *ptr++ = '\\';
	*ptr++ = '"';
      } else {
	WCHAR *pend = ptr + dwSlashCount;
	while (ptr < pend)
	  *ptr++ = '\\';
      }
    } else if (quoted) {
      *ptr++ = '"';
    }
  }

  *ptr++ = '\0';

  return result;
}

BOOL
GetProcessBitness(HANDLE hProcess, PBITNESS pBitness)
{
  BOOL bIsWow64 = FALSE;

  // On 64-bit Windows, 32-bit applications run in WOW64
  if (fnIsWow64Process) {
    if (!fnIsWow64Process(hProcess, &bIsWow64))
      return FALSE;

    if (bIsWow64) {
      *pBitness = BITNESS_32_BIT_WOW64;
      return TRUE;
    }
  }

  // Otherwise, we're native bitness for the system
  SYSTEM_INFO si;
  fnGetSystemInfo(&si);

  switch (si.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
  case PROCESSOR_ARCHITECTURE_ARM64:
  case PROCESSOR_ARCHITECTURE_IA64:
    *pBitness = BITNESS_64_BIT;
    break;
  default:
    *pBitness = BITNESS_32_BIT;
    break;
  }

  return TRUE;
}

namespace {
  struct IMAGE_NT_HEADER_FIXED {
    DWORD 	      Signature;
    IMAGE_FILE_HEADER FileHeader;
  };

  struct ARGX_SECTION_DATA32 {
    DWORD     dwMagic;
    DWORD     dwArgc;
    ULONG     pszArgv;
  };

  struct ARGX_SECTION_DATA64 {
    DWORD     dwMagic;
    DWORD     dwArgc;
    DWORD64 pszArgv;
  };

  const char pe00[4] = { 'P', 'E', 0, 0 };
  const BYTE argxSection[8] = { 'A', 'r', 'g', 'X', 0, 0, 0, 0 };
}

BOOL GetImageBaseAddress(HANDLE hProcess,
			 BITNESS bitness,
			 DWORD64* pImageBaseAddr)
{
  *pImageBaseAddr = 0;

  // Grab the PEB base address
  PROCESS_BASIC_INFORMATION64 pbi;
  ULONG ulRetLength = 0;
  NTSTATUS ntResult = fnNtQueryInformationProcess(hProcess,
						  ProcessBasicInformation,
						  &pbi,
						  sizeof(pbi),
						  &ulRetLength);

  if (!NT_SUCCESS(ntResult)) {
    SetLastError(ntResult);
    return FALSE;
  }
  
  DWORD64 pebBase = (DWORD64)pbi.PebBaseAddress;

  switch (bitness) {
  case BITNESS_32_BIT:
    {
      innards::PEB32 peb;

      if (!ArgxReadProcessMemory(hProcess,
				 pebBase,
				 &peb,
				 sizeof(peb),
				 NULL))
	return FALSE;

      *pImageBaseAddr = peb.ImageBaseAddress;
    }
    break;
  case BITNESS_32_BIT_WOW64:
  case BITNESS_64_BIT:
    {
      innards::PEB64 peb;

      if (!ArgxReadProcessMemory(hProcess,
				 pebBase,
				 &peb,
				 sizeof(peb),
				 NULL))
	return FALSE;

      *pImageBaseAddr = peb.ImageBaseAddress;
    }
    break;
  }

  return TRUE;
}

BOOL FindArgXSection32(HANDLE hProcess,
		       DWORD64 imageBaseAddr,
		       DWORD64* pArgXSectionAddr)
{
  // Now read the IMAGE_DOS_HEADER from ImageBaseAddress
  IMAGE_DOS_HEADER dosHeader;

  if (!ArgxReadProcessMemory(hProcess,
			     imageBaseAddr,
			     &dosHeader,
			     sizeof(dosHeader),
			     NULL))
    return FALSE;

  // That gets us to the IMAGE_NT_HEADERS
  DWORD64 pNtHeader = imageBaseAddr + dosHeader.e_lfanew;
  IMAGE_NT_HEADER_FIXED ntHeader;

  if (!ArgxReadProcessMemory(hProcess,
			     pNtHeader,
			     &ntHeader,
			     sizeof(ntHeader),
			     NULL))
    return FALSE;

  if (!EqualMemory(&ntHeader.Signature, pe00, 4))
    return FALSE;

  // The sections start after the header
  DWORD64 pSections = (pNtHeader + sizeof(ntHeader)
			 + ntHeader.FileHeader.SizeOfOptionalHeader);
  size_t len = sizeof(IMAGE_SECTION_HEADER) * ntHeader.FileHeader.NumberOfSections;
  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)Allocate(len);

  if (!ArgxReadProcessMemory(hProcess,
			     pSections,
			     sections,
			     len,
			     NULL)) {
    Free(sections);
    return FALSE;
  }

  // Look for the ArgX section
  for (unsigned n = 0; n < ntHeader.FileHeader.NumberOfSections; ++n) {
    if (EqualMemory(sections[n].Name, argxSection, 8)) {
      // Found the ArgX section; check it
      if (sections[n].Misc.VirtualSize < sizeof(ARGX_SECTION_DATA32))
	continue;
      if ((sections[n].Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE)) != (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE))
	continue;

      DWORD64 argxAddr = sections[n].VirtualAddress + imageBaseAddr;
      ARGX_SECTION_DATA32 argxData;
      if (!ArgxReadProcessMemory(hProcess,
				 argxAddr,
				 &argxData,
				 sizeof(argxData),
				 NULL)) {
	Free(sections);
	return FALSE;
      }

      if (argxData.dwMagic != ARGX_MAGIC_INIT) {
	Free(sections);
	return FALSE;
      }

      *pArgXSectionAddr = argxAddr;
      Free(sections);
      return TRUE;
    }
  }

  Free(sections);
  return FALSE;
}

BOOL FindArgXSection64(HANDLE hProcess,
		       DWORD64 imageBaseAddr,
		       DWORD64* pArgXSectionAddr)
{
  // Now read the IMAGE_DOS_HEADER from ImageBaseAddress
  IMAGE_DOS_HEADER dosHeader;

  if (!ArgxReadProcessMemory(hProcess,
			     imageBaseAddr,
			     &dosHeader,
			     sizeof(dosHeader),
			     NULL))
    return FALSE;

  // That gets us to the IMAGE_NT_HEADERS
  DWORD64 pNtHeader = imageBaseAddr + dosHeader.e_lfanew;
  IMAGE_NT_HEADER_FIXED ntHeader;

  if (!ArgxReadProcessMemory(hProcess,
			     pNtHeader,
			     &ntHeader,
			     sizeof(ntHeader),
			     NULL))
    return FALSE;

  if (!EqualMemory(&ntHeader.Signature, pe00, 4))
    return FALSE;

  // The sections start after the header
  DWORD64 pSections = (pNtHeader + sizeof(ntHeader)
			 + ntHeader.FileHeader.SizeOfOptionalHeader);
  size_t len = sizeof(IMAGE_SECTION_HEADER) * ntHeader.FileHeader.NumberOfSections;
  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)Allocate(len);

  if (!ArgxReadProcessMemory(hProcess,
			     pSections,
			     sections,
			     len,
			     NULL)) {
    Free(sections);
    return FALSE;
  }

  // Look for the ArgX section
  for (unsigned n = 0; n < ntHeader.FileHeader.NumberOfSections; ++n) {
    if (EqualMemory(sections[n].Name, argxSection, 8)) {
      // Found the ArgX section; check it
      if (sections[n].Misc.VirtualSize < sizeof(ARGX_SECTION_DATA64))
	continue;
      if ((sections[n].Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE)) != (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE))
	continue;

      DWORD64 argxAddr = sections[n].VirtualAddress + imageBaseAddr;
      ARGX_SECTION_DATA32 argxData;
      if (!ArgxReadProcessMemory(hProcess,
				 argxAddr,
				 &argxData,
				 sizeof(argxData),
				 NULL)) {
	Free(sections);
	return FALSE;
      }

      if (argxData.dwMagic != ARGX_MAGIC_INIT) {
	Free(sections);
	return FALSE;
      }

      *pArgXSectionAddr = argxAddr;
      Free(sections);
      return TRUE;
    }
  }

  Free(sections);
  return FALSE;
}

BOOL WriteArguments32(HANDLE hProcess,
		      DWORD64 pArgXSectionAddr,
		      LPCWSTR* lpArgv,
		      DWORD dwArgc)
{
  DWORD dwListSize = sizeof(ULONG) * dwArgc;
  ULONG* args = (ULONG*)Allocate(dwListSize + sizeof(DWORD) * dwArgc);
  DWORD* argLen = (DWORD*)((BYTE*)args + dwListSize);;
  DWORD dwOffset = 0;
  for (DWORD n = 0; n < dwArgc; ++n) {
    args[n] = dwOffset;
    argLen[n] = static_cast<DWORD>(2 * (lstrlenW(lpArgv[n]) + 1));
    dwOffset += argLen[n];
  }

  LPVOID lpvArgs = VirtualAllocEx(hProcess,
				  NULL,
				  dwOffset + dwListSize,
				  MEM_COMMIT,
				  PAGE_READWRITE);

  if (!lpvArgs) {
    Free(args);
    return FALSE;
  }

  for (DWORD n = 0; n < dwArgc; ++n) {
    args[n] += (ULONG)(UINT_PTR)lpvArgs + dwListSize;

    if (!WriteProcessMemory(hProcess,
			    (LPVOID)(UINT_PTR)args[n],
			    lpArgv[n],
			    argLen[n],
			    NULL)) {
      Free(args);
      return FALSE;
    }
  }

  if (!WriteProcessMemory(hProcess,
			  lpvArgs,
			  args,
			  dwListSize,
			  NULL)) {
    Free(args);
    return FALSE;
  }

  Free(args);

  // Update the ArgX section
  ARGX_SECTION_DATA32 argxData;

  argxData.dwMagic = ARGX_MAGIC;
  argxData.dwArgc = dwArgc;
  argxData.pszArgv = (ULONG)(UINT_PTR)lpvArgs;

  if (!WriteProcessMemory(hProcess,
			  (LPVOID)pArgXSectionAddr,
			  &argxData,
			  sizeof(argxData),
			  NULL)) {
    return FALSE;
  }

  return TRUE;
}

BOOL WriteArguments64(HANDLE hProcess,
		      DWORD64 pArgXSectionAddr,
		      LPCWSTR* lpArgv,
		      DWORD dwArgc)
{
  DWORD dwListSize = sizeof(DWORD64) * dwArgc;
  DWORD64* args = (DWORD64*)Allocate(dwListSize + sizeof(DWORD) * dwArgc);
  DWORD* argLen = (DWORD*)((BYTE*)args + dwListSize);
  DWORD dwOffset = 0;
  for (DWORD n = 0; n < dwArgc; ++n) {
    args[n] = dwOffset;
    argLen[n] = static_cast<DWORD>(2 * (lstrlenW(lpArgv[n]) + 1));
    dwOffset += argLen[n];
  }

  DWORD64 lpvArgs = ArgxVirtualAllocEx(hProcess,
				       NULL,
				       static_cast<DWORD64>(dwOffset) + dwListSize,
				       MEM_COMMIT,
				       PAGE_READWRITE);

  if (!lpvArgs) {
    Free(args);
    return FALSE;
  }

  for (DWORD n = 0; n < dwArgc; ++n) {
    args[n] += lpvArgs + dwListSize;

    if (!ArgxWriteProcessMemory(hProcess,
				args[n],
				lpArgv[n],
				argLen[n],
				NULL)) {
      Free(args);
      return FALSE;
    }
  }

  if (!ArgxWriteProcessMemory(hProcess,
			      lpvArgs,
			      args,
			      dwListSize,
			      NULL)) {
    Free(args);
    return FALSE;
  }

  // Update the ArgX section
  ARGX_SECTION_DATA64 argxData;

  argxData.dwMagic = ARGX_MAGIC;
  argxData.dwArgc = dwArgc;
  argxData.pszArgv = (DWORD64)lpvArgs;

  if (!ArgxWriteProcessMemory(hProcess,
			      pArgXSectionAddr,
			      &argxData,
			      sizeof(argxData),
			      NULL)) {
    return FALSE;
  }

  return TRUE;
}

BOOL
ArgxReadProcessMemory(HANDLE hProcess, DWORD64 addr, LPVOID pData, SIZE_T len, SIZE_T* bytesRead)
{
#ifndef _WIN64
  if (fnNtWow64ReadVirtualMemory64) {
    NTSTATUS res;
    ULONG64 ul64BytesRead;
    res = fnNtWow64ReadVirtualMemory64(hProcess, addr, pData, len, &ul64BytesRead);
    if (bytesRead)
      *bytesRead = (SIZE_T)ul64BytesRead;
    return NT_SUCCESS(res);
  }
#endif
  return ReadProcessMemory(hProcess, (LPVOID)addr, pData, len, bytesRead);
}

BOOL
ArgxWriteProcessMemory(HANDLE hProcess, DWORD64 addr, LPCVOID pData, SIZE_T len, SIZE_T* bytesWritten)
{
#ifndef _WIN64 
  if (fnNtWow64ReadVirtualMemory64) {
    NTSTATUS res;
    ULONG64 ul64BytesRead;
    res = fnNtWow64WriteVirtualMemory64(hProcess, addr, pData, len, &ul64BytesRead);
    if (bytesWritten)
      *bytesWritten = (SIZE_T)ul64BytesRead;
    return NT_SUCCESS(res);
  }
#endif
  return WriteProcessMemory(hProcess, (LPVOID)addr, pData, len, bytesWritten);
}

DWORD64
ArgxVirtualAllocEx(HANDLE hProcess, DWORD64 addr, SIZE_T len, DWORD flAllocationType, DWORD flProtect)
{
#ifndef _WIN64
  if (fnNtWow64AllocateVirtualMemory64) {
    NTSTATUS res;
    ULONG64 ul64RegionSize = len;
    res = fnNtWow64AllocateVirtualMemory64(hProcess, &addr, 0, &ul64RegionSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(res))
      return 0;
    return addr;
  }
#endif
  return (DWORD64)VirtualAllocEx(hProcess, (LPVOID)addr, len, flAllocationType, flProtect);
}

} // namespace
