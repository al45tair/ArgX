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

// ArgX version of CreateProcess()
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

// ArgX version of CreateProcessAsUser()
BOOL ARGXAPI ArgxCreateProcessAsUserW(HANDLE		    hToken,
				      LPCWSTR		    lpApplicationName,
				      LPCWSTR*		    lpArgv,
				      DWORD		    dwArgc,
				      LPSECURITY_ATTRIBUTES lpProcessAttributes,
				      LPSECURITY_ATTRIBUTES lpThreadAttributes,
				      BOOL		    bInheritHandles,
				      DWORD		    dwCreationFlags,
				      LPVOID		    lpEnvironment,
				      LPCWSTR		    lpCurrentDirectory,
				      LPSTARTUPINFOW	    lpStartupInfo,
				      LPPROCESS_INFORMATION lpProcessInformation);
BOOL ARGXAPI ArgxCreateProcessAsUserA(HANDLE 		    hToken,
				      LPCSTR		    lpApplicationName,
				      LPCSTR*		    lpArgv,
				      DWORD		    dwArgc,
				      LPSECURITY_ATTRIBUTES lpProcessAttributes,
				      LPSECURITY_ATTRIBUTES lpThreadAttributes,
				      BOOL		    bInheritHandles,
				      DWORD		    dwCreationFlags,
				      LPVOID		    lpEnvironment,
				      LPCSTR		    lpCurrentDirectory,
				      LPSTARTUPINFOA	    lpStartupInfo,
				      LPPROCESS_INFORMATION lpProcessInformation);

// Get the argument vector (works with or without ArgX)
BOOL ARGXAPI ArgxGetArgumentsW(PDWORD    pdwArgc,
			       LPCWSTR** plpArgv,
			       BOOL*	 pbUsedArgX);
BOOL ARGXAPI ArgxGetArgumentsA(PDWORD   pdwArgc,
			       LPCSTR** plpArgv,
			       BOOL* 	pbUsedArgX);

// Searches for an executable with the given name; see CreateProcess() for logic.
// Returns memory allocated with LocalAlloc().
LPWSTR ARGXAPI ArgxFindExecutableW(LPCWSTR lpszArgv0);
LPSTR ARGXAPI ArgxFindExecutableA(LPCSTR lpszArgv0);

// Test if an executable supports ArgX or not
BOOL ARGXAPI ArgxIsSupportedByExecutableW(LPCWSTR lpszExecutablePath);
BOOL ARGXAPI ArgxIsSupportedByExecutableA(LPCSTR lpszExecutablePath);

#if _UNICODE
  #define ArgxCreateProcess		ArgxCreateProcessW
  #define ArgxCreateProcessAsUser	ArgxCreateProcessAsUserW
  #define ArgxGetArguments		ArgxGetArgumentsW
  #define ArgxFindExecutable		ArgxFindExecutableW
  #define ArgxIsSupportedByExecutable	ArgxIsSupportedByExecutableW
#else
  #define ArgxCreateProcess		ArgxCreateProcessA
  #define ArgxCreateProcessAsUser	ArgxCreateProcessAsUserA
  #define ArgxGetArguments		ArgxGetArgumentsA
  #define ArgxFindExecutable		ArgxFindExecutableA
  #define ArgxIsSupportedByExecutable	ArgxIsSupportedByExecutableA
#endif

#ifdef __cplusplus
}
#endif

#endif /* ARGX_H_ */
