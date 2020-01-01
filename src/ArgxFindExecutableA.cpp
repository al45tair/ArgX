/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include "ArgX.h"
#include "utils.hpp"

LPSTR ARGXAPI
ArgxFindExecutableA(LPCSTR lpszArgv0)
{
  LPWSTR lpszArgv0W = argx_utils::ConvertMultiByteToWideString(lpszArgv0);

  if (!lpszArgv0W)
    return NULL;

  LPWSTR lpszResultW = ArgxFindExecutableW(lpszArgv0W);
  DWORD dwErr = GetLastError();

  if (!lpszResultW) {
    argx_utils::FreeConvertedString(lpszArgv0W);
    SetLastError(dwErr);
    return NULL;
  }

  argx_utils::FreeConvertedString(lpszArgv0W);
  LPSTR lpszResultA = argx_utils::ConvertWideToMultiByteString(lpszResultW);
  LocalFree((HLOCAL)lpszResultW);

  if (!lpszResultA)
    return NULL;

  SetLastError(dwErr);
  return lpszResultA;
}
