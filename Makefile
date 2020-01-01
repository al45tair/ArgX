#
#  ArgX - Better command line processing for Windows.
#
#  Copyright (c) 2019 Alastair J. Houghton.
#

#
#  N.B. This makefile is for GNU Make
#

$(info +--------------------------------------------------------------------+)
$(info |                                                                    |)
$(info |  ArgX - Better command line processing for Windows                 |)
$(info |                                                                    |)
$(info |  Copyright (c) 2019 Alastair J. Houghton.                          |)
$(info |                                                                    |)
$(info +--------------------------------------------------------------------+)
$(info  )

# Set up for Visual C++
include msvc.mk

CFLAGS:=-nologo -O1 -W4 -WX -Iinclude
CPPFLAGS:=$(CFLAGS) -EHsc

LIBSRCS:=ArgxCreateProcess.cpp \
	 ArgxCreateProcessA.cpp \
	 ArgxGetArguments.cpp \
	 ArgxGetArgumentsA.cpp \
	 ArgxFindExecutable.cpp \
	 ArgxFindExecutableA.cpp \
	 ArgxIsSupportedByExecutable.cpp \
	 utils.cpp
HEADERS:=include/ArgX.h src/PEB.hpp src/utils.hpp
LIB32OBJS:=$(LIBSRCS:%.cpp=build/x86/%.obj)
LIB64OBJS:=$(LIBSRCS:%.cpp=build/x64/%.obj)

TESTLIBS:=kernel32.lib shell32.lib shlwapi.lib advapi32.lib
TESTPROGS:=argxtest argxrun argxwhich argxsupported
TESTEXES:=$(TESTPROGS:%=build/x86/%a.exe) $(TESTPROGS:%=build/x86/%w.exe) \
	  $(TESTPROGS:%=build/x64/%a.exe) $(TESTPROGS:%=build/x64/%w.exe)

UNICODE:=-DUNICODE -D_UNICODE

export INCLUDE

build/x86/%.obj: src/%.cpp
	@if [[ ! -d build/x86 ]]; then mkdir -p build/x86; fi
	$(CL32) -c $(CPPFLAGS) -Fo$@ $<

build/x64/%.obj: src/%.cpp
	@if [[ ! -d build/x64 ]]; then mkdir -p build/x64; fi
	$(CL64) -c $(CPPFLAGS) -Fo$@ $<

build/x86/%a.exe: export LIB=$(LIB32)
build/x86/%a.exe: test/%.cpp lib/ArgX32.lib
	@if [[ ! -d build/x86 ]]; then mkdir -p build/x86; fi
	$(CL32) $(CPPFLAGS) -Fobuild/x86/ -Fe$@ $^ $(TESTLIBS)

build/x64/%a.exe: export LIB=$(LIB64)
build/x64/%a.exe: test/%.cpp lib/ArgX64.lib
	@if [[ ! -d build/x64 ]]; then mkdir -p build/x64; fi
	$(CL64) $(CPPFLAGS) -Fobuild/x64/ -Fe$@ $^ $(TESTLIBS)

build/x86/%w.exe: export LIB=$(LIB32)
build/x86/%w.exe: test/%.cpp lib/ArgX32.lib
	@if [[ ! -d build/x86 ]]; then mkdir -p build/x86; fi
	$(CL32) $(UNICODE) $(CPPFLAGS) -Fobuild/x86/ -Fe$@ $^ $(TESTLIBS)

build/x64/%w.exe: export LIB=$(LIB64)
build/x64/%w.exe: test/%.cpp lib/ArgX64.lib
	@if [[ ! -d build/x64 ]]; then mkdir -p build/x64; fi
	$(CL64) $(UNICODE) $(CPPFLAGS) -Fobuild/x64/ -Fe$@ $^ $(TESTLIBS)

.PHONY: all libs clean test tests dist

all:	libs

libs:	lib/ArgX32.lib lib/ArgX64.lib

clean:
	$(RM) -rf build lib/*

tests:	$(TESTEXES)

test:	tests
	scripts/test.sh

dist:	libs
	scripts/make-dist.sh

$(LIB32OBJS): $(HEADERS)

$(LIB64OBJS): $(HEADERS)

lib/ArgX32.lib: $(LIB32OBJS)
	@if [[ ! -d lib ]]; then mkdir -p lib; fi
	$(AR) -nologo -out:$@ $(LIB32OBJS)

lib/ArgX64.lib: $(LIB64OBJS)
	@if [[ ! -d lib ]]; then mkdir -p lib; fi
	$(AR) -nologo -out:$@ $(LIB64OBJS)
