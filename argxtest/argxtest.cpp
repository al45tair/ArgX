#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <ArgX.h>
#include <cstdio>

int wmain(void)
{
  DWORD dwArgc;
  LPCWSTR *lpArgv;

  BOOL argx = ArgxGetArgumentsW(&dwArgc, &lpArgv);

  if (argx) {
    wprintf(L"Using ArgX\n");
  } else {
    wprintf(L"Not using ArgX\n");
  }

  for (DWORD n = 0; n < dwArgc; ++n) {
    wprintf(L"%2lu: %p - %s\n", n, lpArgv[n], lpArgv[n]);
  }

  return 0;
}
