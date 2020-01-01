/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include "utils.hpp"

// N.B. The string converters need to use LocalAlloc()/LocalFree() because
//      of the API contract for ArgxFindExecutableA().

LPWSTR argx_utils::ConvertMultiByteToWideString(LPCSTR psz) {
    int ret = MultiByteToWideChar(CP_ACP, 0, psz, -1, NULL, 0);

    if (!ret)
      return NULL;

    LPWSTR pwsz = (LPWSTR)LocalAlloc(LMEM_FIXED, ret * sizeof(WCHAR));

    if (!pwsz)
      return NULL;

    ret = MultiByteToWideChar(CP_ACP, 0, psz, -1, pwsz, ret);

    if (!ret) {
      DWORD dwErr = GetLastError();
      LocalFree((HLOCAL)pwsz);
      SetLastError(dwErr);
      return NULL;
    }

    return pwsz;
  }

void argx_utils::FreeConvertedString(LPWSTR pwsz) {
  if (pwsz)
    LocalFree((HLOCAL)pwsz);
}

LPSTR argx_utils::ConvertWideToMultiByteString(LPCWSTR pwsz) {
  int ret = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS,
				pwsz, -1,
				NULL, 0, NULL, NULL);
  if (!ret)
    return NULL;

  LPSTR psz = (LPSTR)LocalAlloc(LMEM_FIXED, ret);

  if (!psz)
    return NULL;

  ret = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS,
			    pwsz, -1,
			    psz, ret,
			    NULL, NULL);

  if (!ret)
    return NULL;

  return psz;
}

void argx_utils::FreeConvertedString(LPSTR psz) {
  if (psz)
    LocalFree((HLOCAL)psz);
}
