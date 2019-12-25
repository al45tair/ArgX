/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#include "pch.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <limits.h>

#include "ArgX.h"

namespace {
  LPCWSTR* ConvertArgv(DWORD dwArgc, LPCSTR* lpArgv) {
    // Work out how much space we need for the Argv array
    SIZE_T totalStringSize = 0;

    for (DWORD n = 0; n < dwArgc; ++n) {
      int ret = MultiByteToWideChar(CP_ACP, 0,
				    lpArgv[n], -1,
				    NULL, 0);

      if (!ret)
	return NULL;

      totalStringSize += ret;
    }

    SIZE_T totalSize = sizeof(LPCWSTR) * dwArgc + sizeof(WCHAR) * totalStringSize;
    LPCWSTR* lpArgvW = (LPCWSTR*)HeapAlloc(GetProcessHeap(), 0, totalSize);

    if (!lpArgvW)
      return NULL;

    LPWSTR lpStr = (LPWSTR)(lpArgvW + dwArgc);
    SIZE_T remainingStringSize = totalStringSize;

    // Convert the Argv array
    for (DWORD n = 0; n < dwArgc; ++n) {
      lpArgvW[n] = lpStr;

      int bufSiz = remainingStringSize <= INT_MAX ? (int)remainingStringSize : INT_MAX;
      int ret = MultiByteToWideChar(CP_ACP, 0,
				    lpArgv[n], -1,
				    lpStr, bufSiz);

      if (!ret) {
	DWORD dwErr = GetLastError();
	HeapFree(GetProcessHeap(), 0, lpArgvW);
	SetLastError(dwErr);
	return NULL;
      }

      lpStr += ret;
      remainingStringSize -= ret;
    }

    return lpArgvW;
  }

  void FreeConvertedArgv(LPCWSTR* lpArgv) {
    if (lpArgv)
      HeapFree(GetProcessHeap(), 0, lpArgv);
  }

  LPWSTR ConvertMultiByteString(LPCSTR psz) {
    int ret = MultiByteToWideChar(CP_ACP, 0, psz, -1, NULL, 0);

    if (!ret)
      return NULL;

    LPWSTR pwsz = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, ret * sizeof(WCHAR));

    if (!pwsz)
      return NULL;

    ret = MultiByteToWideChar(CP_ACP, 0, psz, -1, pwsz, ret);

    if (!ret) {
      DWORD dwErr = GetLastError();
      HeapFree(GetProcessHeap(), 0, pwsz);
      SetLastError(dwErr);
      return NULL;
    }

    return pwsz;
  }

  void FreeConvertedString(LPWSTR pwsz) {
    if (pwsz)
      HeapFree(GetProcessHeap(), 0, pwsz);
  }
}

BOOL ARGXAPI
ArgxCreateProcessA(LPCSTR			lpApplicationName,
		   LPCSTR*			lpArgv,
		   DWORD			dwArgc,
		   LPSECURITY_ATTRIBUTES	lpProcessAttributes,
		   LPSECURITY_ATTRIBUTES	lpThreadAttributes,
		   BOOL				bInheritHandles,
		   DWORD			dwCreationFlags,
		   LPVOID			lpEnvironment,
		   LPCSTR			lpCurrentDirectory,
		   LPSTARTUPINFOA		lpStartupInfo,
		   LPPROCESS_INFORMATION	lpProcessInformation)
{
  // We don't defer to kernel32 for the -A version of this function.
  // If you're using it and Microsoft's behaves differently, too bad.
  // Don't use the -A version :-)

  if (!lpArgv || !dwArgc) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  BOOL bResult = FALSE;
  LPWSTR lpAppNameW = NULL;
  LPWSTR lpCurrentDirW = NULL;
  LPCWSTR* lpArgvW = NULL;
  STARTUPINFOEXW startupInfo;

  ZeroMemory(&startupInfo, sizeof(startupInfo));

  if (lpApplicationName) {
    lpAppNameW = ConvertMultiByteString(lpApplicationName);

    if (!lpAppNameW)
      goto quickexit;
  }

  if (lpCurrentDirectory) {
    lpCurrentDirW = ConvertMultiByteString(lpCurrentDirectory);

    if (!lpCurrentDirW)
      goto quickexit;
  }

  lpArgvW = ConvertArgv(dwArgc, lpArgv);
  if (!lpArgvW)
    goto quickexit;

  // Convert the STARTUPINFO structure

  if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) {
    if (lpStartupInfo->cb != sizeof(STARTUPINFOEXA)) {
      SetLastError(ERROR_INVALID_PARAMETER);
      return FALSE;
    }

    LPSTARTUPINFOEXA lpStartupInfoEx = (LPSTARTUPINFOEXA)lpStartupInfo;
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.lpAttributeList = lpStartupInfoEx->lpAttributeList;
  } else {
    startupInfo.StartupInfo.cb = sizeof(startupInfo.StartupInfo);
    startupInfo.lpAttributeList = NULL;
  }

  if (lpStartupInfo->lpDesktop) {
    startupInfo.StartupInfo.lpDesktop = ConvertMultiByteString(lpStartupInfo->lpDesktop);

    if (!startupInfo.StartupInfo.lpDesktop)
      goto quickexit;
  }

  if (lpStartupInfo->lpTitle) {
    startupInfo.StartupInfo.lpTitle = ConvertMultiByteString(lpStartupInfo->lpTitle);

    if (!startupInfo.StartupInfo.lpTitle)
      goto quickexit;
  }

  startupInfo.StartupInfo.dwX = lpStartupInfo->dwX;
  startupInfo.StartupInfo.dwY = lpStartupInfo->dwY;
  startupInfo.StartupInfo.dwXSize = lpStartupInfo->dwXSize;
  startupInfo.StartupInfo.dwYSize = lpStartupInfo->dwYSize;
  startupInfo.StartupInfo.dwXCountChars = lpStartupInfo->dwXCountChars;
  startupInfo.StartupInfo.dwYCountChars = lpStartupInfo->dwYCountChars;
  startupInfo.StartupInfo.dwFillAttribute = lpStartupInfo->dwFillAttribute;
  startupInfo.StartupInfo.dwFlags = lpStartupInfo->dwFlags;
  startupInfo.StartupInfo.wShowWindow = lpStartupInfo->wShowWindow;
  startupInfo.StartupInfo.hStdInput = lpStartupInfo->hStdInput;
  startupInfo.StartupInfo.hStdOutput = lpStartupInfo->hStdOutput;
  startupInfo.StartupInfo.hStdError = lpStartupInfo->hStdError;

  bResult = ArgxCreateProcessW(lpAppNameW,
			       lpArgvW,
			       dwArgc,
			       lpProcessAttributes,
			       lpThreadAttributes,
			       bInheritHandles,
			       dwCreationFlags,
			       lpEnvironment,
			       lpCurrentDirW,
			       (LPSTARTUPINFOW)&startupInfo,
			       lpProcessInformation);

 quickexit:
  DWORD dwErr = GetLastError();
  FreeConvertedString(lpAppNameW);
  FreeConvertedString(lpCurrentDirW);
  FreeConvertedArgv(lpArgvW);
  FreeConvertedString(startupInfo.StartupInfo.lpDesktop);
  FreeConvertedString(startupInfo.StartupInfo.lpTitle);
  SetLastError(dwErr);
  return bResult;
}

