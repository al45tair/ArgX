ArgX Specification
==================

This is **version 1.0** of this specification.

Processes that support the ArgX protocol are expected to adhere to
this specification.  They *do not* have to use the ArgX library code
from this project to do so.

1. Supporting ArgX in a client
------------------------------

To indicate that your program supports receiving arguments using the
ArgX mechanism, it must place a section within its executable image
with the name "ArgX".  This section must contain the following data:

======  ====  ===========  ========================
Offset  Size  Name         Meaning
------  ----  -----------  ------------------------
     0     4  ``dwMagic``    Magic number (see below)
     4     4  ``dwArgc``     Argument count
     8   4/8  ``pszArgv``    Argument vector pointer
======  ====  ===========  ========================

The magic number must consist of the bytes::

  61 78 00 00    a x . .

to indicate support for this version of the ArgX specification.  The
two zero bytes are reserved to indicate future, incompatible, versions
of this specification.

Other members of the structure should be set to zero.

When an ArgX-supporting parent process starts a subprocess that itself
supports ArgX, the parent will initialise the ``dwArgc`` and
``pszArgv`` members, and will change ``dwMagic`` to hold the following
bytes::

  41 58 00 00    A X . .

The child process, by checking the value of the ``dwMagic`` field, can
test whether or not its parent has provided an argument vector using
the ArgX mechanism, in which case it *should* use the contents of the
argument vector in preference to the flat command line string supplied
by the operating system.

2. Supporting ArgX in a parent process
--------------------------------------

A parent process that supports ArgX can only use the ArgX protocol if
it can locate the "ArgX" section in the subprocess's runtime image.
It must take care when doing this, and *must* fall back to using the
flat command line mechanism if there is any doubt about the subprocess
it is starting.  In particular, it must check:

- That the subprocess has an ArgX section.
- That the ArgX section is at least large enough to hold the ArgX
  data mentioned above, noting that for 64-bit processes the
  ``pszArgv`` pointer will be eight bytes rather than the four bytes
  it would be for a 32-bit process.
- That the dwMagic field has been initialised appropriately.
- That the ArgX section is readable and writable, but not executable.

Parent processes using the ArgX mechanism *should* pass an equivalent
flat command line, formatted in such a way as to generate the same
argument vector if passed to the Windows `CommandLineToArgvW`_
API.

If passing a command line that will not fit in the flat command line,
a parent process *must* indicate a failure if the subprocess does not
support ArgX; if passing to a process that *does* support ArgX, it
*should* set the flat command line to::

  <argv[0]> --ArgX

If this is not possible because the first argument is itself too long,
it is permissible to pass ``NULL`` to the `CreateProcess`_ API
instead of the flat command line.  ArgX-supporting subprocesses should
not see the flat command line string in most cases anyway.

The parent process is responsible for allocating space in its child
process's address space for the argument vector and for the strings to
which that vector points.  It is also responsible for updating the
``dwMagic`` field to indicate to the child that ArgX is in use.

A parent process must ensure that the child process does not execute
code until the ArgX procedure has been completed.  That is, the child
process should be able to test whether ArgX is in use the moment it
starts up; there *must not* be a race between the parent and child.

Parent processes *should* check for the existence of the ArgX process
creation APIs in ``kernel32.dll`` before performing any processing
themselves.  This is to allow Microsoft to take over implementation of
the ArgX protocol in future, should it so wish.

Change log
----------

==========  =======  ======  ======================
Date        Version  Author  Changes
----------  -------  ------  ----------------------
1 Jan 2020    1.0     ajh    Created specification.
==========  =======  ======  ======================

.. _`CommandLineToArgvW`: https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
.. _`CreateProcess`: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
