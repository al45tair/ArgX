#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <ArgX.h>
#include <cstdio>
#include <tchar.h>

int _tmain(int argc, TCHAR **argv)
{
  PROCESS_INFORMATION pi;
  STARTUPINFO si;
  memset(&si, 0, sizeof(si));

  if (argc < 2) {
    _tprintf(_T("usage: argxrun <thing-to-run> <arguments...>\n"));
    return 0;
  }

  _tprintf(_T("Running %s\n"), argv[1]);

  BOOL bRet = ArgxCreateProcess(argv[1],
				(LPCTSTR *)&argv[1],
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
    _tprintf(_T("Failed\n"));
    return 1;
  }

  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  _tprintf(_T("Finished\n"));

  return 0;
}
