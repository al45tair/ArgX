/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#ifndef ARGX_H_
#define ARGX_H_

#include <windows.h>

#define ARGXAPI

#ifdef __cplusplus
extern "C" {
#endif

#define ARGX_MAGIC	((DWORD)0x00005841)
#define ARGX_MAGIC_INIT ((DWORD)0x00007861)

typedef struct {
  DWORD   dwMagic;
  DWORD   dwArgc;
  LPWSTR *pszArgv;
} ARGX_SECTION_DATA;

// N.B. I would strongly recommend using the -W versions of these APIs,
//      because there is no guarantee that any given character can be
//      successfully encoded in the current system ANSI code page.
//
//      Also, for extra confusion, the currently set code page in the
//      Console may not match the system ANSI code page, in which case
//      command line arguments in multi-byte strings will still be in
//      the system ANSI code page IN SPITE OF WHATEVER THE CONSOLE IS
//      USING.  This can cause very confusing behaviour for end users.

BOOL ARGXAPI ArgxCreateProcessW(LPCWSTR			lpApplicationName,
				LPCWSTR*		lpArgv,
				DWORD			dwArgc,
				LPSECURITY_ATTRIBUTES	lpProcessAttributes,
				LPSECURITY_ATTRIBUTES	lpThreadAttributes,
				BOOL			bInheritHandles,
				DWORD			dwCreationFlags,
				LPVOID			lpEnvironment,
				LPCWSTR			lpCurrentDirectory,
				LPSTARTUPINFOW		lpStartupInfo,
				LPPROCESS_INFORMATION	lpProcessInformation);
BOOL ARGXAPI ArgxCreateProcessA(LPCSTR			lpApplicationName,
				LPCSTR*			lpArgv,
				DWORD			dwArgc,
				LPSECURITY_ATTRIBUTES	lpProcessAttributes,
				LPSECURITY_ATTRIBUTES	lpThreadAttributes,
				BOOL			bInheritHandles,
				DWORD			dwCreationFlags,
				LPVOID			lpEnvironment,
				LPCSTR			lpCurrentDirectory,
				LPSTARTUPINFOA		lpStartupInfo,
				LPPROCESS_INFORMATION	lpProcessInformation);

BOOL ARGXAPI ArgxGetArgumentsW(PDWORD    pdwArgc,
			       LPCWSTR** plpArgv,
			       BOOL*	 pbUsedArgX);
BOOL ARGXAPI ArgxGetArgumentsA(PDWORD   pdwArgc,
			       LPCSTR** plpArgv,
			       BOOL* 	pbUsedArgX);

#if _UNICODE
  #define ArgxCreateProcess ArgxCreateProcessW
  #define ArgxGetArguments  ArgxGetArgumentsW
#else
  #define ArgxCreateProcess ArgxCreateProcessA
  #define ArgxGetArguments  ArgxGetArgumentsA
#endif

#ifdef __cplusplus
}
#endif

#endif /* ARGX_H_ */
