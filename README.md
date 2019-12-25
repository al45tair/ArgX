Windows ArgX Specification Version 1.0
======================================

Introduction
------------

Windows' handling of command line arguments historically has been
poor; even in 2019, Windows still passes arguments as a single command
line string, which makes processing arguments error-prone and also
results in unreasonable limits on command line lengths.

This specification aims to fix the situation so that Windows programs
can pass arguments properly and cleanly among themselves without
worrying about exactly how various metacharacters might be interpreted
by subprocesses.  It also aims to remove the current length limits,
for programs that support such things.

How does the command line get passed to a subprocess?
-----------------------------------------------------

When Windows creates a new process, it places a data structure called
the Process Environment Block into that process' address space.  One
of the members of this structure is a pointer to an
RTL_USER_PROCESS_PARAMETERS structure, which contains, as one of its
members, a UNICODE_STRING structure holding the new process' command
line.  This is eventually passed to the C library's start-up code,
which constructs an argv[] array by parsing the string following
various (complicated, and somewhat nonsensical) rules.

This is in contrast to the situation on other operating systems, where
the argv[] array itself is placed directly into the new process'
address space, which avoids constructing a properly escaped command
line and then parsing the same on entry to the new program.

Why are there length limits?
----------------------------

Well, it varies from version to version, but fundamentally the
UNICODE_STRING type uses a USHORT for its length (in UTF-16 code
units).  So you're limited to 32,768 of them (including the NUL), no
matter what you do.

You might see that some people mention a limit of 8,192 characters;
this is the limit built into the command processor, CMD.EXE.

How does ArgX work?
-------------------

The idea is very simple.  When you use the ArgxCreateProcess() API to
start a new process, you pass in an argv[] array.  ArgxCreateProcess()
will construct a flat command line, if it will fit, taking care to
follow Windows' quoting rules (see CommandLineToArgvW() for more
information on those).  If it won't fit, ArgX sets the flat command
line to the string

  /CommandLineTooLong --commandLineTooLong -commandLineTooLong

which hopefully will cause any software you might choose to run to
report an error unless it supports ArgX, in which case it won't be
using the flat command line data anyway.

Next, ArgxCreateProcess() examines the executable image it is starting
to see whether the image contains a section called "ArgX", of the following
form:

  | Offset | Size | Name      | Meaning                  |
  | ------:| ----:| --------- | ------------------------ |
  |      0 |    4 | dwMagic   | Magic number (see below) |
  |      4 |    4 | dwArgc    | Argument count           |
  |      8 |  4/8 | pszArgv   | Argument vector pointer  |

The magic number must be

  61 78 00 00   a x . .

for the ArgX mechanism to activate.  ArgXCreateProcess() updates this
to

  41 58 00 00   A X . .

to indicate to the child process that ArgX is in use, and fills in the
dwArgc and pszArgv entries in the structure.

(The two zero bytes are reserved for future use; in this version of
the ArgX specification, they are both defined to be zero.)

The size of the pszArgv element depends on whether the process is 32
or 64-bit; it always points at a vector of *Unicode* (i.e. UTF-16)
strings, even if you used the ANSI version of ArgxCreateProcess().

How do I use ArgX?
------------------

Well, you don't need to mess about creating special sections in your
executable.  Instead, just link to the ArgX static library, which will
do the necessary for you.  Then call ArgxGetArgumentsW() to obtain the
argument vector.  This will work whether or not the ArgX mechanism is
active; it returns TRUE if ArgX was used and FALSE otherwise.

If you want to execute a subprocess, instead of using CreateProcessW(),
use the ArgxCreateProcessW() API, which takes similar arguments to
CreateProcessW(), with the exception that it has lpArgv and dwArgc
arguments instead of lpCmdLine.  ArgxCreateProcessW() handles all of
the details of the ArgX mechanism, and it should be a straightforward
API swap in 99% of cases.

What about ANSI functions?
--------------------------

The ArgX library *does* provide ANSI equivalents for
ArgxGetArgumentsW() and ArgxCreateProcessW(), but I don't recommend
using them.  Why?  Two reasons:

1. The current ANSI code page cannot encode all Unicode characters,
   but filenames (in particular) *can* contain Unicode characters.  If
   you use ANSI-encoded arguments, your program may fail to work with
   the user's files.

2. The Console code page does not necessarily (and will not in
   general) match the system's current ANSI code page, but the ANSI
   functions use the current ANSI code page.  This could be very
   confusing indeed for the user if you were to, for instance, display
   a string you received in an ANSI argument vector, because the
   output encoding (the console code page) differs from the argument
   encoding (the system's current ANSI code page).

These problems can be avoided completely by just using the -W versions
of the functions (or by defining _UNICODE).
