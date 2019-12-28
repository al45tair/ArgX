#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <ArgX.h>
#include <cstdio>
#include <tchar.h>

int _tmain(void)
{
  DWORD dwArgc;
  LPCTSTR *lpArgv;
  BOOL bUsedArgX;

  BOOL ret = ArgxGetArguments(&dwArgc, &lpArgv, &bUsedArgX);

  if (!ret) {
    _tprintf(_T("Failed to get arguments\n"));
    return 1;
  }

  if (bUsedArgX) {
    _tprintf(_T("Using ArgX\n"));
  } else {
    _tprintf(_T("Not using ArgX\n"));
  }

  for (DWORD n = 0; n < dwArgc; ++n) {
    _tprintf(_T("%2lu: %p - %s\n"), n, lpArgv[n], lpArgv[n]);
  }

  return 0;
}
