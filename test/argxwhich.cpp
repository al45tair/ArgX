#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <ArgX.h>
#include <cstdio>
#include <tchar.h>

int _tmain(int argc, TCHAR **argv)
{
  if (argc < 2) {
    _tprintf(_T("usage: argxwhich <name-of-program>\n"
		"\n"
		"Locates the specified executable using the same search path as\n"
		"CreateProcess().\n"));
    return 0;
  }

  LPTSTR executable = ArgxFindExecutable(argv[1]);

  if (!executable) {
    _tprintf(_T("%s not found\n"), argv[1]);
    return 1;
  }

  _tprintf(_T("%s\n"), executable);
  return 0;
}
