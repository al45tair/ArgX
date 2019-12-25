/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#include "pch.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <shellapi.h>

#include "ArgX.h"

#pragma section("ArgX", read, write)
namespace {
  __declspec(allocate("ArgX")) ARGX_SECTION_DATA argxData = { ARGX_MAGIC_INIT, 0, 0 };
}

BOOL ARGXAPI
ArgxGetArgumentsW(PDWORD    pdwArgc,
		  LPCWSTR** plpArgv)
{
  if (argxData.dwMagic != ARGX_MAGIC) {
    LPWSTR pszCmdline = GetCommandLineW();
    int numArgs;
    LPWSTR *args = CommandLineToArgvW(pszCmdline, &numArgs);

    *pdwArgc = numArgs;
    *plpArgv = (LPCWSTR*)args;
    return FALSE;
  }

  *pdwArgc = argxData.dwArgc;
  *plpArgv = const_cast<LPCWSTR*>(argxData.pszArgv);

  return TRUE;
}
