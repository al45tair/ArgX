#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <ArgX.h>
#include <cstdio>

int wmain(int argc, wchar_t **argv)
{
  PROCESS_INFORMATION pi;
  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  
  if (argc < 2) {
    wprintf(L"usage: argxrun <thing-to-run> <arguments...>\n");
    return 0;
  }

  wprintf(L"Running %s\n", argv[1]);

  BOOL bRet = ArgxCreateProcessW(argv[1],
				 (LPCWSTR *)&argv[1],
				 argc - 1,
				 NULL,
				 NULL,
				 FALSE,
				 0,
				 NULL,
				 NULL,
				 &si,
				 &pi);

  if (!bRet) {
    wprintf(L"Failed\n");
    return 1;
  }

  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  wprintf(L"Finished\n");

  return 0;
}
