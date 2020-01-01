/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

#include "ArgX.h"
#include "PEB.hpp"
#include "utils.hpp"

#define ARGX_MAXIMUM_FLAT_LENGTH 32767

namespace {

  HMODULE hNtDll = NULL;
  HMODULE hKernel32Dll = NULL;

  HANDLE hProcessHeap = NULL;

  // PROCESS_BASIC_INFORMATION, but always 64-bit
  typedef struct _PROCESS_BASIC_INFORMATION64 {
    DWORD64 Reserved1;
    DWORD64 PebBaseAddress;
    DWORD64 Reserved2[2];
    DWORD64 UniqueProcessId;
    DWORD64 Reserved3;
  } PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

  typedef void (__stdcall *LPFN_GETSYSTEMINFO)(LPSYSTEM_INFO);
  typedef NTSTATUS (NTAPI *LPFN_NTQUERYINFOPROCESS)(HANDLE, PROCESSINFOCLASS,
						    PVOID, ULONG, PULONG);
  typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

  LPFN_GETSYSTEMINFO fnGetSystemInfo;
  LPFN_ISWOW64PROCESS fnIsWow64Process;
  LPFN_NTQUERYINFOPROCESS fnNtQueryInformationProcess;

#ifndef _WIN64
  typedef NTSTATUS (NTAPI *LPFN_NTWOW64READMEM64)(HANDLE, ULONG64, PVOID,
						  ULONG64, PULONG64);
  typedef NTSTATUS (NTAPI *LPFN_NTWOW64WRITEMEM64)(HANDLE, ULONG64, LPCVOID,
						   ULONG64, PULONG64);
  typedef NTSTATUS (NTAPI *LPFN_NTWOW64ALLOCMEM64)(HANDLE, PULONG64, ULONG64,
						   PULONG64, ULONG, ULONG);

  LPFN_NTWOW64READMEM64 fnNtWow64ReadVirtualMemory64;
  LPFN_NTWOW64WRITEMEM64 fnNtWow64WriteVirtualMemory64;
  LPFN_NTWOW64ALLOCMEM64 fnNtWow64AllocateVirtualMemory64;
#endif

  typedef BOOL (__stdcall *LPFN_ARGXCREATEPROCESSW)(LPCWSTR, LPCWSTR*, DWORD,
						    LPSECURITY_ATTRIBUTES,
						    LPSECURITY_ATTRIBUTES, BOOL,
						    DWORD, LPVOID, LPCWSTR,
						    LPSTARTUPINFOW,
						    LPPROCESS_INFORMATION);
  typedef BOOL (__stdcall *LPFN_ARGXCREATEPROCESSASUSERW)(HANDLE,
							  LPCWSTR, LPCWSTR*,
							  DWORD,
							  LPSECURITY_ATTRIBUTES,
							  LPSECURITY_ATTRIBUTES,
							  BOOL,
							  DWORD, LPVOID, LPCWSTR,
							  LPSTARTUPINFOW,
							  LPPROCESS_INFORMATION);

  LPFN_ARGXCREATEPROCESSW fnArgxCreateProcessW;
  LPFN_ARGXCREATEPROCESSASUSERW fnArgxCreateProcessAsUserW;

  typedef enum {
    BITNESS_UNKNOWN = 0,
    BITNESS_WOW64 = 0x1000,

    BITNESS_32_BIT = 32,
    BITNESS_32_BIT_WOW64 = (BITNESS_32_BIT|BITNESS_WOW64),
    BITNESS_64_BIT = 64
  } BITNESS, *PBITNESS;

  BOOL CALLBACK InitArgxCreateFunction(PINIT_ONCE InitOnce, PVOID Parameter,
				       PVOID *lpContext);

  INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

  BOOL ArgxInit() {
    return InitOnceExecuteOnce(&initOnce,
			       InitArgxCreateFunction,
			       NULL,
			       NULL);
  }

  PVOID ArgxAllocate(SIZE_T length) {
    return HeapAlloc(hProcessHeap, 0, length);
  }

  void ArgxFree(PVOID ptr) {
    if (ptr)
      HeapFree(hProcessHeap, 0, ptr);
  }

  class ProcessException {
  public:
    ProcessException(DWORD dwErr) : m_dwErr(dwErr) {}
    DWORD getErrorCode() const { return m_dwErr; }
  private:
    DWORD m_dwErr;
  };

  class Process {
  public:
    Process(LPCWSTR* lpArgv, DWORD dwArgc)
      : m_bSupportsArgX(FALSE), m_hProcess(NULL),
	m_lpArgv(lpArgv), m_dwArgc(dwArgc),
	m_bitness(BITNESS_UNKNOWN),
	m_imageBaseAddress(0), m_argXSectionAddress(0)
    { }

    virtual void start() = 0;
    virtual void resume() = 0;
    virtual void abort() = 0;

    BOOL execute();

    LPWSTR packArgv(LPCWSTR* lpArgv, DWORD dwArgc);
    BITNESS getBitness();
    DWORD64 getImageBaseAddress();
    BOOL supportsArgX();
    void injectArguments();

  protected:
    BOOL     m_bSupportsArgX;
    HANDLE   m_hProcess;
    LPCWSTR* m_lpArgv;
    DWORD    m_dwArgc;

  private:
    void findArgXSection();
    void findArgXSection32();
    void findArgXSection64();
    void injectArgX32();
    void injectArgX64();

    BOOL readMemory(DWORD64 addr, LPVOID pData, SIZE_T len, SIZE_T* bytesRead);
    BOOL writeMemory(DWORD64 addr, LPCVOID pData, SIZE_T len, SIZE_T* bytesWritten);
    DWORD64 allocMemory(DWORD64 addr, SIZE_T len, DWORD flAllocationType, DWORD flProtect);

    BITNESS m_bitness;
    DWORD64 m_imageBaseAddress;
    DWORD64 m_argXSectionAddress;
  };

  class StandardProcess : public Process {
  public:
    StandardProcess(LPCWSTR			lpApplicationName,
		    LPCWSTR*			lpArgv,
		    DWORD			dwArgc,
		    LPSECURITY_ATTRIBUTES	lpProcessAttributes,
		    LPSECURITY_ATTRIBUTES	lpThreadAttributes,
		    BOOL			bInheritHandles,
		    DWORD			dwCreationFlags,
		    LPVOID			lpEnvironment,
		    LPCWSTR			lpCurrentDirectory,
		    LPSTARTUPINFOW		lpStartupInfo,
		    LPPROCESS_INFORMATION 	lpProcessInformation)
      : Process(lpArgv, dwArgc),
	m_pszExecutablePath(NULL),
	m_lpApplicationName(lpApplicationName),
	m_lpProcessAttributes(lpProcessAttributes),
	m_lpThreadAttributes(lpThreadAttributes),
	m_bInheritHandles(bInheritHandles),
	m_dwCreationFlags(dwCreationFlags),
	m_lpEnvironment(lpEnvironment),
	m_lpCurrentDirectory(lpCurrentDirectory),
	m_lpStartupInfo(lpStartupInfo),
	m_lpProcessInformation(lpProcessInformation)
    {
      m_lpProcessInformation->hProcess = NULL;
      m_lpProcessInformation->hThread = NULL;

      if (!m_lpApplicationName && lpArgv && dwArgc) {
	m_lpApplicationName = m_pszExecutablePath
	  = ArgxFindExecutableW(lpArgv[0]);
      }
    }

    ~StandardProcess() {
      if (m_pszExecutablePath)
	LocalFree((HLOCAL)m_pszExecutablePath);
    }

    void start();
    void resume();
    void abort();

  protected:
    LPWSTR			m_pszExecutablePath;
    LPCWSTR			m_lpApplicationName;
    LPSECURITY_ATTRIBUTES	m_lpProcessAttributes;
    LPSECURITY_ATTRIBUTES	m_lpThreadAttributes;
    BOOL			m_bInheritHandles;
    DWORD			m_dwCreationFlags;
    LPVOID			m_lpEnvironment;
    LPCWSTR			m_lpCurrentDirectory;
    LPSTARTUPINFOW		m_lpStartupInfo;
    LPPROCESS_INFORMATION	m_lpProcessInformation;
  };

  class OtherUserProcess : public StandardProcess {
  public:
    OtherUserProcess(HANDLE 			hToken,
		     LPCWSTR			lpApplicationName,
		     LPCWSTR*			lpArgv,
		     DWORD			dwArgc,
		     LPSECURITY_ATTRIBUTES	lpProcessAttributes,
		     LPSECURITY_ATTRIBUTES	lpThreadAttributes,
		     BOOL			bInheritHandles,
		     DWORD			dwCreationFlags,
		     LPVOID			lpEnvironment,
		     LPCWSTR			lpCurrentDirectory,
		     LPSTARTUPINFOW		lpStartupInfo,
		     LPPROCESS_INFORMATION 	lpProcessInformation)
      : StandardProcess(lpApplicationName,
			lpArgv,
			dwArgc,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation),
	m_hToken(hToken)
    {}

    void start();

  protected:
    HANDLE m_hToken;
  };

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
    DWORD64 pszArgv;
  };

  const char pe00[4] = { 'P', 'E', 0, 0 };
  const BYTE argxSection[8] = { 'A', 'r', 'g', 'X', 0, 0, 0, 0 };
} // namespace

BOOL ARGXAPI
ArgxCreateProcessW(LPCWSTR			lpApplicationName,
		   LPCWSTR*			lpArgv,
		   DWORD			dwArgc,
		   LPSECURITY_ATTRIBUTES	lpProcessAttributes,
		   LPSECURITY_ATTRIBUTES	lpThreadAttributes,
		   BOOL				bInheritHandles,
		   DWORD			dwCreationFlags,
		   LPVOID			lpEnvironment,
		   LPCWSTR			lpCurrentDirectory,
		   LPSTARTUPINFOW		lpStartupInfo,
		   LPPROCESS_INFORMATION	lpProcessInformation)
{
  // Make sure we have our function pointers
  if (!ArgxInit())
    return FALSE;

  // If kernel32 implements this function, call that implementation instead;
  // this is to allow Microsoft to take over implementation of ArgxCreateProcessW
  // in some future version of Windows.
  if (fnArgxCreateProcessW) {
    return fnArgxCreateProcessW(lpApplicationName,
				lpArgv,
				dwArgc,
				lpProcessAttributes,
				lpThreadAttributes,
				bInheritHandles,
				dwCreationFlags,
				lpEnvironment,
				lpCurrentDirectory,
				lpStartupInfo,
				lpProcessInformation);
  }

  StandardProcess process(lpApplicationName,
			  lpArgv,
			  dwArgc,
			  lpProcessAttributes,
			  lpThreadAttributes,
			  bInheritHandles,
			  dwCreationFlags,
			  lpEnvironment,
			  lpCurrentDirectory,
			  lpStartupInfo,
			  lpProcessInformation);

  return process.execute();
}

BOOL ARGXAPI
ArgxCreateProcessAsUserW(HANDLE			hToken,
			 LPCWSTR		lpApplicationName,
			 LPCWSTR*		lpArgv,
			 DWORD			dwArgc,
			 LPSECURITY_ATTRIBUTES	lpProcessAttributes,
			 LPSECURITY_ATTRIBUTES	lpThreadAttributes,
			 BOOL			bInheritHandles,
			 DWORD			dwCreationFlags,
			 LPVOID			lpEnvironment,
			 LPCWSTR		lpCurrentDirectory,
			 LPSTARTUPINFOW		lpStartupInfo,
			 LPPROCESS_INFORMATION	lpProcessInformation)
{
  // Make sure we have our function pointers
  if (!ArgxInit())
    return FALSE;

  // If kernel32 implements this function, call that implementation instead;
  // this is to allow Microsoft to take over implementation of
  // ArgxCreateProcessAsUserW in some future version of Windows.
  if (fnArgxCreateProcessAsUserW) {
    return fnArgxCreateProcessAsUserW(hToken,
				      lpApplicationName,
				      lpArgv,
				      dwArgc,
				      lpProcessAttributes,
				      lpThreadAttributes,
				      bInheritHandles,
				      dwCreationFlags,
				      lpEnvironment,
				      lpCurrentDirectory,
				      lpStartupInfo,
				      lpProcessInformation);
  }

  OtherUserProcess process(hToken,
			   lpApplicationName,
			   lpArgv,
			   dwArgc,
			   lpProcessAttributes,
			   lpThreadAttributes,
			   bInheritHandles,
			   dwCreationFlags,
			   lpEnvironment,
			   lpCurrentDirectory,
			   lpStartupInfo,
			   lpProcessInformation);

  return process.execute();
}

namespace {

BOOL CALLBACK InitArgxCreateFunction(PINIT_ONCE, PVOID, PVOID *)
{
  hProcessHeap = GetProcessHeap();
  if (!hProcessHeap)
    return FALSE;

  hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtDll)
    return FALSE;

  hKernel32Dll = GetModuleHandleW(L"kernel32.dll");
  if (!hKernel32Dll)
    return FALSE;

  // Look for the function in kernel32, so that Microsoft can override this
  // implementation
  fnArgxCreateProcessW = reinterpret_cast<LPFN_ARGXCREATEPROCESSW>(GetProcAddress(hKernel32Dll, "ArgxCreateProcessW"));
  fnArgxCreateProcessAsUserW = reinterpret_cast<LPFN_ARGXCREATEPROCESSASUSERW>(GetProcAddress(hKernel32Dll, "ArgxCreateProcessAsUserW"));

  // Look up various low-level functions we need
  fnIsWow64Process = reinterpret_cast<LPFN_ISWOW64PROCESS>(GetProcAddress(hKernel32Dll, "IsWow64Process"));
  fnGetSystemInfo = reinterpret_cast<LPFN_GETSYSTEMINFO>(GetProcAddress(hKernel32Dll, "GetNativeSystemInfo"));
  if (!fnGetSystemInfo)
    fnGetSystemInfo = reinterpret_cast<LPFN_GETSYSTEMINFO>(GetProcAddress(hKernel32Dll, "GetSystemInfo"));
  fnNtQueryInformationProcess = reinterpret_cast<LPFN_NTQUERYINFOPROCESS>(GetProcAddress(hNtDll, "NtQueryInformationProcess"));

#ifndef _WIN64
  // Get some Wow64 pointers, if this is a Wow64 process
  LPFN_NTQUERYINFOPROCESS fnWowQueryInfoProcess;
  fnWowQueryInfoProcess = reinterpret_cast<LPFN_NTQUERYINFOPROCESS>(GetProcAddress(hNtDll, "NtWow64QueryInformationProcess64"));

  if (fnWowQueryInfoProcess)
    fnNtQueryInformationProcess = fnWowQueryInfoProcess;

  fnNtWow64ReadVirtualMemory64 = reinterpret_cast<LPFN_NTWOW64READMEM64>(GetProcAddress(hNtDll, "NtWow64ReadVirtualMemory64"));
  fnNtWow64WriteVirtualMemory64 = reinterpret_cast<LPFN_NTWOW64WRITEMEM64>(GetProcAddress(hNtDll, "NtWow64WriteVirtualMemory64"));
  fnNtWow64AllocateVirtualMemory64 = reinterpret_cast<LPFN_NTWOW64ALLOCMEM64>(GetProcAddress(hNtDll, "NtWow64ArgxAllocateVirtualMemory64"));
#endif

  return TRUE;
}

} // namespace

LPWSTR
Process::packArgv(LPCWSTR* lpArgv, DWORD dwArgc)
{
  DWORD dwLen = 6;

  /* We do this in two passes; the first works out how long the result will
     be; the second actually fills it in */
  for (DWORD dwArg = 0; dwArg < dwArgc; ++dwArg) {
    LPCWSTR szArg = lpArgv[dwArg];

    const WCHAR *ptr = szArg;
    DWORD dwSlashCount = 0;
    BOOL quoted = FALSE;
    while (*ptr) {
      WCHAR ch = *ptr++;

      switch (ch) {
      case '\\':
	++dwSlashCount;
	break;
      case '"':
	if (dwSlashCount)
	  dwLen += dwSlashCount * 2;
	dwLen += 2;
	dwSlashCount = 0;
	break;
      case ' ':
      case '\t':
	if (!quoted) {
	  quoted = TRUE;
	  dwLen += 2;
	}
      default:
	if (dwSlashCount) {
	  dwLen += dwSlashCount;
	  dwSlashCount = 0;
	}
	++dwLen;
      }
    }

    if (dwSlashCount) {
      if (quoted)
	dwLen += dwSlashCount * 2 + 1;
      else
	dwLen += dwSlashCount;
    }
  }

  // Spaces and NULL
  dwLen += dwArgc;

  if (dwLen >= ARGX_MAXIMUM_FLAT_LENGTH)
    return NULL;

  LPWSTR result = (LPWSTR)ArgxAllocate(dwLen * sizeof(WCHAR));
  WCHAR *ptr = result;

  for (DWORD dwArg = 0; dwArg < dwArgc; ++dwArg) {
    LPCWSTR szArg = lpArgv[dwArg];
    const WCHAR *pt2 = szArg;
    DWORD dwSlashCount = 0;
    BOOL quoted = FALSE;

    if (dwArg)
      *ptr++ = ' ';

    while (*pt2) {
      WCHAR ch = *pt2++;
      if (ch == ' ' || ch == '\t') {
	quoted = TRUE;
	break;
      }
    }

    if (quoted)
      *ptr++ = '"';

    pt2 = szArg;
    while (*pt2) {
      WCHAR ch = *pt2++;

      switch (ch) {
      case '\\':
	++dwSlashCount;
	break;
      case '"':
	{
	  WCHAR *pend = ptr + 2 * dwSlashCount;
	  while (ptr < pend)
	    *ptr++ = '\\';
	  dwSlashCount = 0;
	  *ptr++ = '\\';
	  *ptr++ = '"';
	}
	break;
      default:
	{
	  WCHAR *pend = ptr + dwSlashCount;
	  while (ptr < pend)
	    *ptr++ = '\\';
	  dwSlashCount = 0;
	  *ptr++ = ch;
	}
	break;
      }
    }

    if (dwSlashCount) {
      if (quoted) {
	WCHAR *pend = ptr + 2 * dwSlashCount;
	while (ptr < pend)
	  *ptr++ = '\\';
	*ptr++ = '"';
      } else {
	WCHAR *pend = ptr + dwSlashCount;
	while (ptr < pend)
	  *ptr++ = '\\';
      }
    } else if (quoted) {
      *ptr++ = '"';
    }
  }

  *ptr++ = '\0';

  return result;
}

BITNESS
Process::getBitness()
{
  if (m_bitness != BITNESS_UNKNOWN)
    return m_bitness;

  BOOL bIsWow64 = FALSE;

  // On 64-bit Windows, 32-bit applications run in WOW64
  if (fnIsWow64Process) {
    if (!fnIsWow64Process(m_hProcess, &bIsWow64))
      throw ProcessException(GetLastError());

    if (bIsWow64) {
      m_bitness = BITNESS_32_BIT_WOW64;
      return m_bitness;
    }
  }

  // Otherwise, we're native bitness for the system
  SYSTEM_INFO si;
  fnGetSystemInfo(&si);

  switch (si.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
  case PROCESSOR_ARCHITECTURE_ARM64:
  case PROCESSOR_ARCHITECTURE_IA64:
    m_bitness = BITNESS_64_BIT;
    break;
  default:
    m_bitness = BITNESS_32_BIT;
    break;
  }

  return m_bitness;
}

DWORD64
Process::getImageBaseAddress()
{
  if (m_imageBaseAddress)
    return m_imageBaseAddress;

  BITNESS bitness = getBitness();

  // Grab the PEB base address
  PROCESS_BASIC_INFORMATION64 pbi;
  ULONG ulRetLength = 0;
  NTSTATUS ntResult = fnNtQueryInformationProcess(m_hProcess,
						  ProcessBasicInformation,
						  &pbi,
						  sizeof(pbi),
						  &ulRetLength);

  if (!NT_SUCCESS(ntResult)) {
    SetLastError(ntResult);
    return 0;
  }

  DWORD64 pebBase = (DWORD64)pbi.PebBaseAddress;

  switch (bitness) {
  case BITNESS_32_BIT:
    {
      innards::PEB32 peb;

      if (!readMemory(pebBase,
		      &peb,
		      sizeof(peb),
		      NULL))
	return 0;

      m_imageBaseAddress = peb.ImageBaseAddress;
    }
    break;
  case BITNESS_32_BIT_WOW64:
  case BITNESS_64_BIT:
    {
      innards::PEB64 peb;

      if (!readMemory(pebBase,
		      &peb,
		      sizeof(peb),
		      NULL))
	return 0;

      m_imageBaseAddress = peb.ImageBaseAddress;
    }
    break;
  }

  return m_imageBaseAddress;
}

BOOL
Process::supportsArgX()
{
  findArgXSection();

  return m_argXSectionAddress != 0;
}

void
Process::findArgXSection() {
  if (m_argXSectionAddress)
    return;

  switch (getBitness()) {
  case BITNESS_UNKNOWN:
    throw ProcessException(ERROR_INVALID_PARAMETER);
  case BITNESS_32_BIT:
  case BITNESS_32_BIT_WOW64:
    findArgXSection32();
    break;
  case BITNESS_64_BIT:
    findArgXSection64();
    break;
  }
}

void
Process::injectArguments() {
  findArgXSection();

  if (!m_argXSectionAddress)
    return;

  switch (getBitness()) {
  case BITNESS_UNKNOWN:
    throw ProcessException(ERROR_INVALID_PARAMETER);
  case BITNESS_32_BIT:
  case BITNESS_32_BIT_WOW64:
    injectArgX32();
    break;
  case BITNESS_64_BIT:
    injectArgX64();
    break;
  }
}

void
Process::findArgXSection32()
{
  if (m_argXSectionAddress)
    return;

  // Make sure we know the image base address
  DWORD64 imageBaseAddr = getImageBaseAddress();

  // Now read the IMAGE_DOS_HEADER from ImageBaseAddress
  IMAGE_DOS_HEADER dosHeader;

  if (!readMemory(imageBaseAddr,
		  &dosHeader,
		  sizeof(dosHeader),
		  NULL))
    return;

  // That gets us to the IMAGE_NT_HEADERS
  DWORD64 pNtHeader = imageBaseAddr + dosHeader.e_lfanew;
  IMAGE_NT_HEADER_FIXED ntHeader;

  if (!readMemory(pNtHeader,
		  &ntHeader,
		  sizeof(ntHeader),
		  NULL))
    return;

  if (!argx_utils::EqualMemory(&ntHeader.Signature, pe00, 4))
    return;

  // The sections start after the header
  DWORD64 pSections = (pNtHeader + sizeof(ntHeader)
			 + ntHeader.FileHeader.SizeOfOptionalHeader);
  size_t len = sizeof(IMAGE_SECTION_HEADER) * ntHeader.FileHeader.NumberOfSections;
  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)ArgxAllocate(len);

  if (!readMemory(pSections,
		  sections,
		  len,
		  NULL)) {
    ArgxFree(sections);
    return;
  }

  // Look for the ArgX section
  for (unsigned n = 0; n < ntHeader.FileHeader.NumberOfSections; ++n) {
    if (argx_utils::EqualMemory(sections[n].Name, argxSection, 8)) {
      // Found the ArgX section; check it
      if (sections[n].Misc.VirtualSize < sizeof(ARGX_SECTION_DATA32))
	continue;
      if ((sections[n].Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE)) != (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE))
	continue;

      DWORD64 argxAddr = sections[n].VirtualAddress + imageBaseAddr;
      ARGX_SECTION_DATA32 argxData;
      if (!readMemory(argxAddr,
		      &argxData,
		      sizeof(argxData),
		      NULL)) {
	ArgxFree(sections);
	return;
      }

      if (argxData.dwMagic != ARGX_MAGIC_INIT) {
	ArgxFree(sections);
	return;
      }

      ArgxFree(sections);
      m_argXSectionAddress = argxAddr;
      return;
    }
  }

  ArgxFree(sections);
  return;
}

void
Process::findArgXSection64()
{
  if (m_argXSectionAddress)
    return;

  // Find the image base address
  DWORD64 imageBaseAddr = getImageBaseAddress();

  // Now read the IMAGE_DOS_HEADER from ImageBaseAddress
  IMAGE_DOS_HEADER dosHeader;

  if (!readMemory(imageBaseAddr,
		  &dosHeader,
		  sizeof(dosHeader),
		  NULL))
    return;

  // That gets us to the IMAGE_NT_HEADERS
  DWORD64 pNtHeader = imageBaseAddr + dosHeader.e_lfanew;
  IMAGE_NT_HEADER_FIXED ntHeader;

  if (!readMemory(pNtHeader,
		  &ntHeader,
		  sizeof(ntHeader),
		  NULL))
    return;

  if (!argx_utils::EqualMemory(&ntHeader.Signature, pe00, 4))
    return;

  // The sections start after the header
  DWORD64 pSections = (pNtHeader + sizeof(ntHeader)
			 + ntHeader.FileHeader.SizeOfOptionalHeader);
  size_t len = sizeof(IMAGE_SECTION_HEADER) * ntHeader.FileHeader.NumberOfSections;
  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)ArgxAllocate(len);

  if (!readMemory(pSections,
		  sections,
		  len,
		  NULL)) {
    ArgxFree(sections);
    return;
  }

  // Look for the ArgX section
  for (unsigned n = 0; n < ntHeader.FileHeader.NumberOfSections; ++n) {
    if (argx_utils::EqualMemory(sections[n].Name, argxSection, 8)) {
      // Found the ArgX section; check it
      if (sections[n].Misc.VirtualSize < sizeof(ARGX_SECTION_DATA64))
	continue;
      if ((sections[n].Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE)) != (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE))
	continue;

      DWORD64 argxAddr = sections[n].VirtualAddress + imageBaseAddr;
      ARGX_SECTION_DATA32 argxData;
      if (!readMemory(argxAddr,
		      &argxData,
		      sizeof(argxData),
		      NULL)) {
	ArgxFree(sections);
	return;
      }

      if (argxData.dwMagic != ARGX_MAGIC_INIT) {
	ArgxFree(sections);
	return;
      }

      ArgxFree(sections);
      m_argXSectionAddress = argxAddr;
      return;
    }
  }

  ArgxFree(sections);
  return;
}

void
Process::injectArgX32()
{
  DWORD dwListSize = sizeof(ULONG) * m_dwArgc;
  ULONG* args = (ULONG*)ArgxAllocate(dwListSize + sizeof(DWORD) * m_dwArgc);
  DWORD* argLen = (DWORD*)((BYTE*)args + dwListSize);;
  DWORD dwOffset = 0;
  for (DWORD n = 0; n < m_dwArgc; ++n) {
    args[n] = dwOffset;
    argLen[n] = static_cast<DWORD>(2 * (lstrlenW(m_lpArgv[n]) + 1));
    dwOffset += argLen[n];
  }

  DWORD64 lpvArgs = allocMemory(NULL,
				dwOffset + dwListSize,
				MEM_COMMIT,
				PAGE_READWRITE);

  if (!lpvArgs) {
    DWORD dwErr = GetLastError();
    ArgxFree(args);
    throw ProcessException(dwErr);
  }

  for (DWORD n = 0; n < m_dwArgc; ++n) {
    args[n] += (ULONG)(UINT_PTR)lpvArgs + dwListSize;

    if (!writeMemory(args[n],
		     m_lpArgv[n],
		     argLen[n],
		     NULL)) {
      DWORD dwErr = GetLastError();
      ArgxFree(args);
      throw ProcessException(dwErr);
    }
  }

  if (!writeMemory(lpvArgs,
		   args,
		   dwListSize,
		   NULL)) {
    DWORD dwErr = GetLastError();
    ArgxFree(args);
    throw ProcessException(dwErr);
  }

  ArgxFree(args);

  // Update the ArgX section
  ARGX_SECTION_DATA32 argxData;

  argxData.dwMagic = ARGX_MAGIC;
  argxData.dwArgc = m_dwArgc;
  argxData.pszArgv = (ULONG)(UINT_PTR)lpvArgs;

  if (!writeMemory(m_argXSectionAddress,
		   &argxData,
		   sizeof(argxData),
		   NULL)) {
    throw ProcessException(GetLastError());
  }
}

void
Process::injectArgX64()
{
  DWORD dwListSize = sizeof(DWORD64) * m_dwArgc;
  DWORD64* args = (DWORD64*)ArgxAllocate(dwListSize + sizeof(DWORD) * m_dwArgc);
  DWORD* argLen = (DWORD*)((BYTE*)args + dwListSize);
  DWORD dwOffset = 0;
  for (DWORD n = 0; n < m_dwArgc; ++n) {
    args[n] = dwOffset;
    argLen[n] = static_cast<DWORD>(2 * (lstrlenW(m_lpArgv[n]) + 1));
    dwOffset += argLen[n];
  }

  DWORD64 lpvArgs = allocMemory(NULL,
				static_cast<DWORD64>(dwOffset) + dwListSize,
				MEM_COMMIT,
				PAGE_READWRITE);

  if (!lpvArgs) {
    DWORD dwErr = GetLastError();
    ArgxFree(args);
    throw ProcessException(dwErr);
  }

  for (DWORD n = 0; n < m_dwArgc; ++n) {
    args[n] += lpvArgs + dwListSize;

    if (!writeMemory(args[n],
		     m_lpArgv[n],
		     argLen[n],
		     NULL)) {
      DWORD dwErr = GetLastError();
      ArgxFree(args);
      throw ProcessException(dwErr);
    }
  }

  if (!writeMemory(lpvArgs,
		   args,
		   dwListSize,
		   NULL)) {
    DWORD dwErr = GetLastError();
    ArgxFree(args);
    throw ProcessException(dwErr);
  }

  // Update the ArgX section
  ARGX_SECTION_DATA64 argxData;

  argxData.dwMagic = ARGX_MAGIC;
  argxData.dwArgc = m_dwArgc;
  argxData.pszArgv = (DWORD64)lpvArgs;

  if (!writeMemory(m_argXSectionAddress,
		   &argxData,
		   sizeof(argxData),
		   NULL)) {
    throw ProcessException(GetLastError());
  }
}

BOOL
Process::readMemory(DWORD64 addr, LPVOID pData, SIZE_T len, SIZE_T* bytesRead)
{
#ifndef _WIN64
  if (fnNtWow64ReadVirtualMemory64) {
    NTSTATUS res;
    ULONG64 ul64BytesRead;
    res = fnNtWow64ReadVirtualMemory64(m_hProcess, addr, pData, len, &ul64BytesRead);
    if (bytesRead)
      *bytesRead = (SIZE_T)ul64BytesRead;
    return NT_SUCCESS(res);
  }
#endif
  return ReadProcessMemory(m_hProcess, (LPVOID)addr, pData, len, bytesRead);
}

BOOL
Process::writeMemory(DWORD64 addr, LPCVOID pData, SIZE_T len, SIZE_T* bytesWritten)
{
#ifndef _WIN64
  if (fnNtWow64ReadVirtualMemory64) {
    NTSTATUS res;
    ULONG64 ul64BytesRead;
    res = fnNtWow64WriteVirtualMemory64(m_hProcess, addr, pData, len, &ul64BytesRead);
    if (bytesWritten)
      *bytesWritten = (SIZE_T)ul64BytesRead;
    return NT_SUCCESS(res);
  }
#endif
  return WriteProcessMemory(m_hProcess, (LPVOID)addr, pData, len, bytesWritten);
}

DWORD64
Process::allocMemory(DWORD64 addr, SIZE_T len, DWORD flAllocationType, DWORD flProtect)
{
#ifndef _WIN64
  if (fnNtWow64AllocateVirtualMemory64) {
    NTSTATUS res;
    ULONG64 ul64RegionSize = len;
    res = fnNtWow64AllocateVirtualMemory64(m_hProcess, &addr, 0, &ul64RegionSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(res))
      return 0;
    return addr;
  }
#endif
  return (DWORD64)VirtualAllocEx(m_hProcess, (LPVOID)addr, len, flAllocationType, flProtect);
}

BOOL
Process::execute()
{
  try {
    start();
    injectArguments();
    resume();
    return TRUE;
  } catch (const ProcessException& e) {
    abort();
    SetLastError(e.getErrorCode());
    return FALSE;
  }
}

void
StandardProcess::start()
{
  if (!m_lpArgv || !m_dwArgc)
    throw ProcessException(ERROR_INVALID_PARAMETER);

  LPWSTR pszCmdline = packArgv(m_lpArgv, m_dwArgc);

  if (!pszCmdline) {
    if (!ArgxIsSupportedByExecutableW(m_lpApplicationName))
      throw ProcessException(ERROR_BAD_LENGTH);

    LPCWSTR args[] = { m_lpArgv[0], L"--ArgX" };
    pszCmdline = packArgv(args, 2);
  }

  try {
    if (!CreateProcessW(m_lpApplicationName,
			pszCmdline,
			m_lpProcessAttributes,
			m_lpThreadAttributes,
			m_bInheritHandles,
			m_dwCreationFlags | CREATE_SUSPENDED,
			m_lpEnvironment,
			m_lpCurrentDirectory,
			m_lpStartupInfo,
			m_lpProcessInformation))
      throw ProcessException(GetLastError());
    ArgxFree(pszCmdline);
    m_hProcess = m_lpProcessInformation->hProcess;
  } catch (...) {
    ArgxFree(pszCmdline);
    throw;
  }
}

void
StandardProcess::resume()
{
  if (!(m_dwCreationFlags & CREATE_SUSPENDED)) {
    if (!ResumeThread(m_lpProcessInformation->hThread))
      throw ProcessException(GetLastError());
  }
}

void
StandardProcess::abort()
{
  if (m_lpProcessInformation->hProcess) {
    TerminateProcess(m_lpProcessInformation->hProcess, 0);
    CloseHandle(m_lpProcessInformation->hProcess);
    CloseHandle(m_lpProcessInformation->hThread);
    m_lpProcessInformation->hProcess = NULL;
    m_lpProcessInformation->hThread = NULL;
  }
}

void
OtherUserProcess::start()
{
  if (!m_lpArgv || !m_dwArgc)
    throw ProcessException(ERROR_INVALID_PARAMETER);

  LPWSTR pszCmdline = packArgv(m_lpArgv, m_dwArgc);

  if (!pszCmdline) {
    if (!ArgxIsSupportedByExecutableW(m_lpApplicationName))
      throw ProcessException(ERROR_BAD_LENGTH);

    LPCWSTR args[] = { m_lpArgv[0], L"--ArgX" };
    pszCmdline = packArgv(args, 2);
  }

  try {
    if (!CreateProcessAsUserW(m_hToken,
			      m_lpApplicationName,
			      pszCmdline,
			      m_lpProcessAttributes,
			      m_lpThreadAttributes,
			      m_bInheritHandles,
			      m_dwCreationFlags | CREATE_SUSPENDED,
			      m_lpEnvironment,
			      m_lpCurrentDirectory,
			      m_lpStartupInfo,
			      m_lpProcessInformation))
      throw ProcessException(GetLastError());
    ArgxFree(pszCmdline);
    m_hProcess = m_lpProcessInformation->hProcess;
  } catch (...) {
    ArgxFree(pszCmdline);
    throw;
  }
}
