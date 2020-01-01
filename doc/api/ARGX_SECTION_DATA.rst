ARGX_SECTION_DATA structure
===========================

A structure corresponding to the ArgX section in the :doc:`../argx-protocol`.

Syntax
------

::

  #define ARGX_MAGIC      ((DWORD)0x00005841)
  #define ARGX_MAGIC_INIT ((DWORD)0x00007861)

  typedef struct {
    DWORD   dwMagic;
    DWORD   dwArgc;
    LPWSTR *pszArgv;
  } ARGX_SECTION_DATA;

Members
-------

``dwMagic``
  In the executable image, should be set to ``ARGX_MAGIC_INIT``; if ArgX
  protocol is in use, this will be updated to ``ARGX_MAGIC``.

``dwArgc``
  A count of the arguments in the argument vector.  In the executable
  image, should be set to zero.

``pszArgv``
  A pointer to the argument vector.  In the executable image, should
  be set to zero.

Remarks
-------

You most likely do not need to use this structure directly; instead,
any call to :doc:`ArgxGetArguments <ArgxGetArguments>` will
automatically result in an appropriately initialised copy of this
structure ending up in the "ArgX" section in your executable image.
This is done by the code at the top of ``src/ArgxGetArguments.cpp``::

  #pragma section("ArgX", read, write)
  namespace {
    __declspec(allocate("ArgX")) ARGX_SECTION_DATA argxData = { ARGX_MAGIC_INIT, 0, 0 };
  }

See also
--------

:doc:`ArgxGetArguments <ArgxGetArguments>`
