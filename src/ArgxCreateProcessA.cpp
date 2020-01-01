/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <limits.h>

#include "ArgX.h"
#include "utils.hpp"

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

      int bufSiz = (remainingStringSize <= INT_MAX
		    ? (int)remainingStringSize : INT_MAX);
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

  BOOL ConvertStartupInfo(DWORD 	   dwCreationFlags,
			  LPSTARTUPINFOA   lpStartupInfoA,
			  LPSTARTUPINFOEXW lpStartupInfoW) {
    if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) {
      if (lpStartupInfoA->cb != sizeof(STARTUPINFOEXA)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
      }

      LPSTARTUPINFOEXA lpStartupInfoEx = (LPSTARTUPINFOEXA)lpStartupInfoA;
      lpStartupInfoW->StartupInfo.cb = sizeof(*lpStartupInfoW);
      lpStartupInfoW->lpAttributeList = lpStartupInfoEx->lpAttributeList;
    } else {
      lpStartupInfoW->StartupInfo.cb = sizeof(lpStartupInfoW->StartupInfo);
      lpStartupInfoW->lpAttributeList = NULL;
    }

    if (lpStartupInfoA->lpDesktop) {
      lpStartupInfoW->StartupInfo.lpDesktop
	= argx_utils::ConvertMultiByteToWideString(lpStartupInfoA->lpDesktop);

      if (!lpStartupInfoW->StartupInfo.lpDesktop)
	return FALSE;
    }

    if (lpStartupInfoA->lpTitle) {
      lpStartupInfoW->StartupInfo.lpTitle
	= argx_utils::ConvertMultiByteToWideString(lpStartupInfoA->lpTitle);

      if (!lpStartupInfoW->StartupInfo.lpTitle)
	return FALSE;
    }

    lpStartupInfoW->StartupInfo.dwX = lpStartupInfoA->dwX;
    lpStartupInfoW->StartupInfo.dwY = lpStartupInfoA->dwY;
    lpStartupInfoW->StartupInfo.dwXSize = lpStartupInfoA->dwXSize;
    lpStartupInfoW->StartupInfo.dwYSize = lpStartupInfoA->dwYSize;
    lpStartupInfoW->StartupInfo.dwXCountChars = lpStartupInfoA->dwXCountChars;
    lpStartupInfoW->StartupInfo.dwYCountChars = lpStartupInfoA->dwYCountChars;
    lpStartupInfoW->StartupInfo.dwFillAttribute = lpStartupInfoA->dwFillAttribute;
    lpStartupInfoW->StartupInfo.dwFlags = lpStartupInfoA->dwFlags;
    lpStartupInfoW->StartupInfo.wShowWindow = lpStartupInfoA->wShowWindow;
    lpStartupInfoW->StartupInfo.hStdInput = lpStartupInfoA->hStdInput;
    lpStartupInfoW->StartupInfo.hStdOutput = lpStartupInfoA->hStdOutput;
    lpStartupInfoW->StartupInfo.hStdError = lpStartupInfoA->hStdError;

    return TRUE;
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
    lpAppNameW = argx_utils::ConvertMultiByteToWideString(lpApplicationName);

    if (!lpAppNameW)
      goto quickexit;
  }

  if (lpCurrentDirectory) {
    lpCurrentDirW = argx_utils::ConvertMultiByteToWideString(lpCurrentDirectory);

    if (!lpCurrentDirW)
      goto quickexit;
  }

  lpArgvW = ConvertArgv(dwArgc, lpArgv);
  if (!lpArgvW)
    goto quickexit;

  // Convert the STARTUPINFO structure
  if (!ConvertStartupInfo(dwCreationFlags, lpStartupInfo, &startupInfo))
    goto quickexit;

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
  argx_utils::FreeConvertedString(lpAppNameW);
  argx_utils::FreeConvertedString(lpCurrentDirW);
  FreeConvertedArgv(lpArgvW);
  argx_utils::FreeConvertedString(startupInfo.StartupInfo.lpDesktop);
  argx_utils::FreeConvertedString(startupInfo.StartupInfo.lpTitle);
  SetLastError(dwErr);
  return bResult;
}

BOOL ARGXAPI
ArgxCreateProcessAsUserA(HANDLE			hToken,
			 LPCSTR			lpApplicationName,
			 LPCSTR*		lpArgv,
			 DWORD			dwArgc,
			 LPSECURITY_ATTRIBUTES	lpProcessAttributes,
			 LPSECURITY_ATTRIBUTES	lpThreadAttributes,
			 BOOL			bInheritHandles,
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
    lpAppNameW = argx_utils::ConvertMultiByteToWideString(lpApplicationName);

    if (!lpAppNameW)
      goto quickexit;
  }

  if (lpCurrentDirectory) {
    lpCurrentDirW = argx_utils::ConvertMultiByteToWideString(lpCurrentDirectory);

    if (!lpCurrentDirW)
      goto quickexit;
  }

  lpArgvW = ConvertArgv(dwArgc, lpArgv);
  if (!lpArgvW)
    goto quickexit;

  // Convert the STARTUPINFO structure
  if (!ConvertStartupInfo(dwCreationFlags, lpStartupInfo, &startupInfo))
    goto quickexit;

  bResult = ArgxCreateProcessAsUserW(hToken,
				     lpAppNameW,
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
  argx_utils::FreeConvertedString(lpAppNameW);
  argx_utils::FreeConvertedString(lpCurrentDirW);
  FreeConvertedArgv(lpArgvW);
  argx_utils::FreeConvertedString(startupInfo.StartupInfo.lpDesktop);
  argx_utils::FreeConvertedString(startupInfo.StartupInfo.lpTitle);
  SetLastError(dwErr);
  return bResult;
}
