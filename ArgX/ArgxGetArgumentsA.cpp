/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#include "pch.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include "ArgX.h"

namespace {
  BOOL CALLBACK InitArgxGetArgumentsA(PINIT_ONCE InitOnce, PVOID Parameter,
				      PVOID *lpContext);

  INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

  DWORD     dwArgc;
  LPCSTR*   lpArgv;
}

BOOL ARGXAPI
ArgxGetArgumentsA(PDWORD   pdwArgc,
		  LPCSTR** plpArgv)
{
  // The first time this is called, and *only* the first time, convert the
  // argv array.
  if (!InitOnceExecuteOnce(&initOnce,
			   InitArgxGetArgumentsA,
			   NULL,
			   NULL))
    return FALSE;

  if (!lpArgv)
    return FALSE;

  *pdwArgc = dwArgc;
  *plpArgv = lpArgv;

  return TRUE;
}

namespace {

BOOL CALLBACK InitArgxGetArgumentsA(PINIT_ONCE, PVOID, PVOID *)
{
  LPCWSTR* lpArgvW;
  HANDLE hProcessHeap = GetProcessHeap();

  dwArgc = 0;
  lpArgv = NULL;

  if (!ArgxGetArgumentsW(&dwArgc, &lpArgvW))
    return FALSE;

  // First, work out how much memory we need for the converted strings
  SIZE_T totalStringSize = 0;

  for (DWORD n = 0; n < dwArgc; ++n) {
    int ret = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS,
				  lpArgvW[n], -1,
				  NULL, 0,
				  NULL,
				  NULL);

    if (!ret)
      return FALSE;

    // No need to +1 for NUL because -1 for the length of the input includes
    // the NUL (which will be converted).
    totalStringSize += ret;
  }

  // Figure out how much memory to allocate
  SIZE_T totalSize = sizeof(LPCSTR) * dwArgc + totalStringSize;
  lpArgv = (LPCSTR*)HeapAlloc(hProcessHeap, 0, totalSize);

  if (!lpArgv)
    return FALSE;

  LPSTR lpStr = (LPSTR)(lpArgv + dwArgc);
  SIZE_T remainingStringSize = totalStringSize;

  for (DWORD n = 0; n < dwArgc; ++n) {
    lpArgv[n] = lpStr;

    int ret = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS,
				  lpArgvW[n], -1,
				  lpStr, remainingStringSize,
				  NULL,
				  NULL);

    if (!ret) {
      DWORD dwErr = GetLastError();
      HeapFree(hProcessHeap, 0, lpArgv);
      SetLastError(dwErr);
      lpArgv = NULL;
      return FALSE;
    }

    lpStr += ret;
    remainingStringSize -= ret;
  }

  return TRUE;
}

}

