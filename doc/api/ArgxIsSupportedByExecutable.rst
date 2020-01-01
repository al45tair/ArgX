ArgxIsSupportedByExecutable function
====================================

Tests if the specified executable supports ArgX, without actually starting it.

Syntax
------

::

  BOOL ArgxIsSuportedByExecutable(LPCTSTR lpszExecutablePath);

Parameters
----------

``lpszExecutablePath``
  The path to the executable to test.  This should be a valid path to
  the executable file; no searching takes place, and no default
  extension is appended.

Return value
------------

If the executable specified by ``lpszExecutablePath`` supports ArgX
protocol, the return value is non-zero; otherwise, the return value is
zero.
