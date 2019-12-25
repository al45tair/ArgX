/*
 * ArgX - Better command line processing for Widnows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#ifndef ARGX_PEB_H_
#define ARGX_PEB_H_

namespace innards {

  typedef DWORD   POINTER32;
  typedef DWORD64 POINTER64;

  template <class PTR>
  struct TEB {
    PTR ExceptionList;
    PTR StackBase;
    PTR StackLimit;
    PTR SubSystemTIB;
    PTR FiberData;
    PTR ArbitraryUserPOinter;
    PTR Self;
    PTR EnvironmentPointer;
    PTR UniqueProcess;
    PTR UniqueThread;
    PTR ActiveRPCHandle;
    PTR ThreadLocalStoragePointer;
    PTR ProcessEnvironmentBlock;
  };

  typedef TEB<POINTER32> TEB32;
  typedef TEB<POINTER64> TEB64;

  template <class PTR>
  struct PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR Flags;
    PTR Mutant;
    PTR ImageBaseAddress;
    PTR Ldr;
    PTR ProcessParameters;
  };

  typedef PEB<POINTER32> PEB32;
  typedef PEB<POINTER64> PEB64;

  template <class PTR>
  struct UNISTR {
    USHORT Length;
    USHORT MaximumLength;
    PTR    Buffer;
  };

  typedef UNISTR<POINTER32> UNISTR32;
  typedef UNISTR<POINTER64> UNISTR64;

  template <class PTR>
  struct CURDIR {
    UNISTR<PTR> DosPath;
    PTR Handle;
  };

  typedef CURDIR<POINTER32> CURDIR32;
  typedef CURDIR<POINTER64> CURDIR64;

  template <class PTR>
  struct RTL_USER_PROCESS_PARAMS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PTR   ConsoleHandle;
    ULONG ConsoleFlags;
    PTR   StandardInput;
    PTR   StandardOutput;
    PTR   StandardError;
    struct CURDIR<PTR> CurrentDirectory;
    struct UNISTR<PTR> DllPath;
    struct UNISTR<PTR> ImagePathName;
    struct UNISTR<PTR> CommandLine;
    PTR   Environment;
  };

  typedef RTL_USER_PROCESS_PARAMS<POINTER32> RTL_USER_PROCESS_PARAMS32;
  typedef RTL_USER_PROCESS_PARAMS<POINTER64> RTL_USER_PROCESS_PARAMS64;

  template <class PTR>
  struct LIST_ENTRY {
    PTR Flink;
    PTR Blink;
  };

  typedef LIST_ENTRY<POINTER32> LIST_ENTRY32;
  typedef LIST_ENTRY<POINTER64> LIST_ENTRY64;

  template <class PTR>
  struct LDR_DATA_TABLE_ENTRY
  {
    LIST_ENTRY<PTR> InLoadOrderLinks;
    LIST_ENTRY<PTR> InMemoryOrderLinks;
    LIST_ENTRY<PTR> InInitializationOrderLinks;
    PTR DllBase;
    PTR EntryPoint;
    union {
      DWORD SizeOfImage;
      PTR Reserved;
    };
    UNISTR<PTR> FullDllName;
    UNISTR<PTR> BaseDllName;
    DWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
  };

  typedef LDR_DATA_TABLE_ENTRY<POINTER32> LDR_DATA_TABLE_ENTRY32;
  typedef LDR_DATA_TABLE_ENTRY<POINTER64> LDR_DATA_TABLE_ENTRY64;

  template <class PTR>
  struct LDR_DATA
  {
    DWORD Length;
    DWORD Initialized;
    PTR   SsHandle;
    LIST_ENTRY<PTR> InLoadOrderModuleList;
    LIST_ENTRY<PTR> InMemoryOrderModuleList;
    LIST_ENTRY<PTR> InInitializationOrderModuleList;
    PTR EntryInProgress;
    DWORD ShutdownInProcess;
    PTR ShutdownThreadId;
  };

  typedef LDR_DATA<POINTER32> LDR_DATA32;
  typedef LDR_DATA<POINTER64> LDR_DATA64;

}

#endif /* ARGX_PEB_H_ */
