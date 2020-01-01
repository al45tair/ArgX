/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include "ArgX.h"
#include "utils.hpp"

namespace {
  struct IMAGE_NT_HEADER_FIXED {
    DWORD 	      Signature;
    IMAGE_FILE_HEADER FileHeader;
  };

  struct ARGX_SECTION_DATA32 {
    DWORD     dwMagic;
    DWORD     dwArgc;
    ULONG     pszArgv;
  };

  struct ARGX_SECTION_DATA64 {
    DWORD     dwMagic;
    DWORD     dwArgc;
    ULONG64   pszArgv;
  };

  const char pe00[4] = { 'P', 'E', 0, 0 };
  const BYTE argxSection[8] = { 'A', 'r', 'g', 'X', 0, 0, 0, 0 };

  BOOL ArgxIsSupportedByFile(HANDLE hFile)
  {
    BOOL bArgXSupported = FALSE;

    if (hFile == INVALID_HANDLE_VALUE)
      return FALSE;

    SetLastError(ERROR_SUCCESS);

    // Read the DOS header first
    IMAGE_DOS_HEADER dosHeader;
    DWORD dwBytesRead;
    DWORD dwRet = SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    if (dwRet == INVALID_SET_FILE_POINTER)
      goto quickexit;

    BOOL bRet = ReadFile(hFile, &dosHeader, sizeof(dosHeader),
			 &dwBytesRead, NULL);

    if (!bRet || dwBytesRead != sizeof(dosHeader))
      goto quickexit;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
      goto quickexit;

    // Now read the NT header
    dwRet = SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);

    if (dwRet == INVALID_SET_FILE_POINTER)
      goto quickexit;

    IMAGE_NT_HEADER_FIXED ntHeader;

    bRet = ReadFile(hFile, &ntHeader, sizeof(ntHeader), &dwBytesRead, NULL);

    if (!bRet || dwBytesRead != sizeof(ntHeader))
      goto quickexit;

    if (!argx_utils::EqualMemory(&ntHeader.Signature, pe00, 4))
      goto quickexit;

    // Pick the correct ARGX_SECTION_DATA structure size
    SIZE_T argXSectionDataSize = sizeof(ARGX_SECTION_DATA32);

    switch (ntHeader.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
      argXSectionDataSize = sizeof(ARGX_SECTION_DATA32);
      break;
    case IMAGE_FILE_MACHINE_AMD64:
      argXSectionDataSize = sizeof(ARGX_SECTION_DATA64);
      break;
    default:
      // We only support x86/x64 for now
      goto quickexit;
    }

    // Scan through the sections
    DWORD sectionOffset = (dosHeader.e_lfanew + sizeof(ntHeader)
			   + ntHeader.FileHeader.SizeOfOptionalHeader);

    dwRet = SetFilePointer(hFile, sectionOffset, NULL, FILE_BEGIN);

    if (dwRet == INVALID_SET_FILE_POINTER)
      goto quickexit;

    for (unsigned n = 0; n < ntHeader.FileHeader.NumberOfSections; ++n) {
      IMAGE_SECTION_HEADER section;

      bRet = ReadFile(hFile, &section, sizeof(section), &dwBytesRead, NULL);

      if (!bRet || dwBytesRead != sizeof(section))
	goto quickexit;

      if (argx_utils::EqualMemory(section.Name, argxSection, 8)) {
	// Found the ArgX section; check it
	if (section.SizeOfRawData < argXSectionDataSize)
	  continue;

	if ((section.Characteristics
	     & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE))
	    != (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE))
	  continue;

	ARGX_SECTION_DATA32 argxData;

	DWORD oldOffset = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);

	dwRet = SetFilePointer(hFile, section.PointerToRawData,
			       NULL, FILE_BEGIN);

	if (dwRet == INVALID_SET_FILE_POINTER)
	  continue;

	bRet = ReadFile(hFile, &argxData, sizeof(argxData), &dwBytesRead, NULL);

	if (bRet && dwBytesRead == sizeof(argxData)
	    && argxData.dwMagic == ARGX_MAGIC_INIT) {
	  bArgXSupported = TRUE;
	  goto quickexit;
	}

	dwRet = SetFilePointer(hFile, oldOffset, NULL, FILE_BEGIN);

	if (dwRet == INVALID_SET_FILE_POINTER)
	  goto quickexit;
      }
    }

  quickexit:
    CloseHandle(hFile);
    return bArgXSupported;
  }
}

BOOL ARGXAPI ArgxIsSupportedByExecutableW(LPCWSTR lpszExecutablePath)
{
  HANDLE hFile = CreateFileW(lpszExecutablePath,
			     GENERIC_READ,
			     FILE_SHARE_READ,
			     NULL,
			     OPEN_EXISTING,
			     FILE_ATTRIBUTE_NORMAL,
			     NULL);

  return ArgxIsSupportedByFile(hFile);
}

BOOL ARGXAPI ArgxIsSupportedByExecutableA(LPCSTR lpszExecutablePath)
{
  HANDLE hFile = CreateFileA(lpszExecutablePath,
			     GENERIC_READ,
			     FILE_SHARE_READ,
			     NULL,
			     OPEN_EXISTING,
			     FILE_ATTRIBUTE_NORMAL,
			     NULL);

  return ArgxIsSupportedByFile(hFile);
}
