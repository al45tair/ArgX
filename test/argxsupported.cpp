#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <ArgX.h>
#include <cstdio>
#include <tchar.h>

int _tmain(int argc, TCHAR **argv)
{
  if (argc < 2) {
    _tprintf(_T("usage: argxsupported <name-of-program>\n"
		"\n"
		"Locates the specified executable using the same search path as\n"
		"CreateProcess(), then determines whether it supports ArgX.\n"));
    return 0;
  }

  LPTSTR executable = ArgxFindExecutable(argv[1]);

  if (!executable) {
    _tprintf(_T("%s not found\n"), argv[1]);
    return 1;
  }

  if (ArgxIsSupportedByExecutable(executable))
    _tprintf(_T("%s supports ArgX\n"), executable);
  else
    _tprintf(_T("%s does not support ArgX\n"), executable);

  return 0;
}
