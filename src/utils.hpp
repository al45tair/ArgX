/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#ifndef ARGX_UTILS_HPP_
#define ARGX_UTILS_HPP_

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

namespace argx_utils {

  LPWSTR ConvertMultiByteToWideString(LPCSTR psz);
  LPSTR  ConvertWideToMultiByteString(LPCWSTR pszw);
  void   FreeConvertedString(LPSTR psz);
  void   FreeConvertedString(LPWSTR psz);

  // Using this avoids bringing in the C runtime just for memcmp(); we only
  // compare 4 or 8 bytes anyway, so the compiler should be able to optimise
  // this.
  inline BOOL EqualMemory(const void *pa, const void *pb, SIZE_T len) {
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

#endif // ARGX_UTILS_HPP_
