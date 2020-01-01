ArgxGetArguments function
=========================

Retrieves the calling process's command line arguments in the form of
an argument vector.  If the ArgX protocol is not in use, this function
will parse the flat command line using the `CommandLineToArgvW`_ API
and return the results.

Syntax
------

::

  BOOL ArgxGetArguments(
          PDWORD    pdwArgc,
	  LPCTSTR** plpArgv,
	  BOOL*     pbUserArgX
       );

Parameters
----------

``pdwArgc``
  A pointer to a ``DWORD`` that will be initialised with a count of
  the number of arguments in the argument vector.  May not be ``NULL``.

``plpArgv``
  Points to a variable that will receive the argument vector pointer.
  May not be ``NULL``.

``pbUserArgX``
  Points to a ``BOOL`` variable that will be set to ``TRUE`` if the
  ArgX mechanism was used to obtain the arguments and ``FALSE``
  otherwise.  If not required, may be ``NULL``.

Return value
------------

If the function succeeds, the return value is nonzero.

If the function fails, it will return zero, with extended error
information supplied via `GetLastError`_.

See also
--------

`CommandLineToArgvW`_

.. _`CommandLineToArgvW`: https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
.. _`GetLastError`: https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
