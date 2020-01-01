ArgxFindExecutable function
===========================

Given the first element of an argument vector, attempts to locate an
executable according to the rules specified in the
:doc:`ArgxCreateProcess <ArgxCreateProcess>` documentation.

Syntax
------

::

  LPTSTR ArgxFindExecutable(LPCTSTR lpszArgv0);

Parameters
----------

``lpszArgv0``
  The name of the executable to find.  This is processed as follows:

  - If ``lpszArgv0`` contains path delimiters, it will be treated as a
    literal path and used directly; otherwise,
  - If ``lpszArgv0`` does not have an extension, the extension “.exe”
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

Return value
------------

If the function succeeds, it returns a string containing the path to
the executable found according to the rules above.  This string should
be released when no longer required, using the `LocalFree`_ function.

If the function fails to find a match, it returns ``NULL``.

See also
--------

:doc:`ArgxCreateProcess <ArgxCreateProcess>`

.. _`LocalFree`: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree
.. _`GetSystemDirectory`: https://docs.microsoft.com/en-gb/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
.. _`GetWindowsDirectory`: https://docs.microsoft.com/en-gb/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
