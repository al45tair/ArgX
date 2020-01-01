Using this library
==================

The ArgX library code is intended to be easy to use; your program can
include the ``ArgX.h`` header file, and link against either
``ArgX32.lib`` or ``ArgX64.lib`` as appropriate.  You will also need
to link some system libraries; presently the set required is
``kernel32.lib``, ``shell32.lib``, ``shlwapi.lib`` and
``advapi32.lib``.

You can then make use of the ArgX API functions defined in the header
file.

As an alternative, you can copy the relevant source files (in the
``src`` folder) directly into your own project.  All the code here is
subject to the MIT License, so this is quite permissible.

Please do not extend or alter the ArgX code in such a way that it
deviates from the specification.
