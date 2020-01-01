ArgxCreateProcess function
==========================

Creates a new process, running in the security context of the calling
process.

This is equivalent to the Windows `CreateProcess`_ API.

Syntax
------

::

  BOOL ArgxCreateProcess(
	  LPCTSTR               lpApplicationName,
	  LPCTSTR*              lpArgv,
	  DWORD                 dwArgc,
	  LPSECURITY_ATTRIBUTES lpProcessAttributes,
	  LPSECURITY_ATTRIBUTES lpThreadAttributes,
	  BOOL                  bInheritHandles,
	  DWORD                 dwCreationFlags,
	  LPVOID                lpEnvironment,
	  LPCTSTR               lpCurrentDirectory,
	  LPSTARTUPINFO         lpStartupInfo,
	  LPPROCESS_INFORMATION lpProcessInformation
       );

Parameters
----------

``lpApplicationName``
  The path to the executable to start.  This string is not subject to
  any path searching, though it may be a relative path.  There is no
  default extension for this parameter.

  If this parameter is ``NULL``, the executable path will be taken
  from the first argument, ``lpArgv[0]``.

``lpArgv``
  The argument vector.  If ``lpApplicationName`` is ``NULL``, the
  first element of the argument vector will be used to locate the
  desired executable.

  In that case:

  - If ``lpArgv[0]`` contains path delimiters, it will be treated as a
    literal path and used directly; otherwise,
  - If ``lpArgv[0]`` does not have an extension, the extension “.exe”
    will be appended automatically.
  - The function will then try to find the executable by looking in
    the following places:

    1. The directory from which the calling application loaded.
    2. The current directory.
    3. The Windows System32 directory (as returned by
       the `GetSystemDirectory`_ API).
    4. The 16-bit Windows System directory, if present.
    5. The Windows directory (as returned by the
       `GetWindowsDirectory`_ API).
    6. The directories listed in the ``PATH`` environment variable.

  This function will *not* modify any of the strings in ``lpArgv``.
  Also note that this function does not suffer from the security hole
  in the `CreateProcess`_ API caused by that function's attempt to
  parse filenames and directory names containing spaces.

  ``lpArgv`` *must not* be ``NULL``.

``dwArgc``
  The number of elements in ``lpArgv``, which must be at least one.

``lpProcessAttributes``
  Describes the desired `SECURITY_ATTRIBUTES`_ for the new process.  May
  be ``NULL``.

``lpThreadAttributes``
  Describes the desired `SECURITY_ATTRIBUTES`_ for the primary thread of
  the new process.  May be ``NULL``.

``bInheritHandles``
  If ``TRUE``, inheritable handles will be inherited by the
  subprocess.  Importantly, inherited handles have the same access
  rights that they have in the parent process, so this needs to be
  used with care.

``dwCreationFlags``
  Flags that control priority class and creation behaviour.  See
  `Process Creation Flags`_ for more information.

``lpEnvironment``
  Points to the environment block for the new process, or ``NULL`` to
  inherit the environment of the parent.

``lpCurrentDirectory``
  If ``NULL``, the new process will start with the same current
  directory as the parent process.  Otherwise, must contain the full
  path to the desired current directory.

``lpStartupInfo``
  Points to a `STARTUPINFO`_ or `STARTUPINFOEX`_ structure.  May
  be ``NULL``.

``lpProcessInformation``
  Points to a `PROCESS_INFORMATION`_ structure that will be filled
  in with handles to the process and its primary thread.  Note that
  these handles *must be closed* when no longer needed.

Return value
------------

If the function succeeds, the return value is nonzero.

If the function fails, it will return zero (i.e. ``FALSE``), with
extended error information supplied via `GetLastError`_.

See also
--------

`CreateProcess`_

.. _`CreateProcess`: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
.. _`GetSystemDirectory`: https://docs.microsoft.com/en-gb/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
.. _`GetWindowsDirectory`: https://docs.microsoft.com/en-gb/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
.. _`GetLastError`: https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
.. _`SECURITY_ATTRIBUTES`: https://docs.microsoft.com/previous-versions/windows/desktop/legacy/aa379560(v=vs.85)
.. _`STARTUPINFO`: https://docs.microsoft.com/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfow
.. _`STARTUPINFOEX`: https://docs.microsoft.com/windows/desktop/api/winbase/ns-winbase-startupinfoexw
.. _`PROCESS_INFORMATION`: https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-process_information
.. _`Process Creation Flags`: https://docs.microsoft.com/windows/desktop/ProcThread/process-creation-flags
