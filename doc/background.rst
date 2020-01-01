Background
==========

Argument passing in C
---------------------

The C standard specifies that programs start running in the
``main`` function, which takes two parameters, ``argc``,
the number of arguments, and ``argv``, an array of pointers to
those arguments.

It doesn't specify exactly how that information gets into your
program, however, and historically DOS and DOS-like systems (including
Windows) have chosen a different approach to their POSIX brethren.

Typical POSIX approach
----------------------

On POSIX systems, the shell is responsible for parsing the command
line into separate arguments.  The upshot of this is that the
arguments arrive in subprocesses already separated, and with any
quoting or escaping supported by the shell already processed.

The shell is also responsible for globbing (that is, expanding any
patterns that the user has entered on the command line, e.g. ``*.txt``).

The advantage of this is that the processing of command lines is
determined entirely by whichever shell the user is using.  The shell
is free to do what it pleases, and subprocesses for the most part do
not care how it goes about its business.

Typical DOS/DOS-like approach
-----------------------------

On DOS and similar systems, the shell is *not* responsible for command
line parsing, and instead passes the entire command line, as a string,
to the subprocess.  This means that subprocesses must take
responsibility for quoting and escaping, as well as globbing.

The upshot of this is that support for quoting, escaping and globbing
tends to be rather patchy and ad-hoc.  Some programs support these
features, and often not in every location/situation in the command
line.

What does Windows do?
---------------------

Well, it is perhaps no surprise that Windows takes the DOS-like
approach, with one concession, namely that there is a Windows API,
`CommandLineToArgvW`_, that will take a flat command line string and
parse it into an argument array for you according to some rather odd
and somewhat counterintuitive rules.

Since that API was only added in Windows 2000, and since up to that
point it was up to the C library's start-up code to do any necessary
parsing, there's a good chance that whatever program you're looking at
doesn't use the API and also that it parses its command line in some
other manner than the one Microsoft clearly expects.

Windows places the command line into a `UNICODE_STRING`_ in the
`RTL_USER_PROCESS_PARAMETERS`_ structure that is pointed to by the
Process Environment Block (or `PEB`_ for short) that it creates in the
new process's address space.  This is the origin of the 32,767
character length limit; the `UNICODE_STRING`_ structure uses a
``USHORT`` for its length (in UTF-16 code units).  So you're limited
to 32,768 of them, including the terminating NUL, no matter what you
do.

(You might also see some people mention a limit of 8,192 characters;
this is a limit built into the command processor, ``CMD.EXE``.)

.. _`CommandLineToArgvW`: https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
.. _`PEB`: https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
.. _`RTL_USER_PROCESS_PARAMETERS`: https://docs.microsoft.com/en-gb/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
.. _`UNICODE_STRING`: https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
