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
CPPFLAGS:=$(CFLAGS)

LIBSRCS:=ArgxCreateProcess.cpp \
	 ArgxCreateProcessA.cpp \
	 ArgxGetArguments.cpp \
	 ArgxGetArgumentsA.cpp
LIB32OBJS:=$(LIBSRCS:%.cpp=build/x86/%.obj)
LIB64OBJS:=$(LIBSRCS:%.cpp=build/x64/%.obj)

TESTLIBS:=kernel32.lib shell32.lib

export INCLUDE

build/x86/%.obj: src/%.cpp build/x86
	$(CL32) -c $(CPPFLAGS) -Fo$@ $<

build/x64/%.obj: src/%.cpp build/x64
	$(CL64) -c $(CPPFLAGS) -Fo$@ $<

.PHONY: all clean test

all:	lib/ArgX32.lib lib/ArgX64.lib

clean:
	$(RM) -rf build lib/*

test:	build/x86/argxtesta.exe build/x86/argxtestw.exe \
	build/x64/argxtesta.exe build/x64/argxtestw.exe \
	build/x86/argxruna.exe build/x86/argxrunw.exe \
	build/x64/argxruna.exe build/x64/argxrunw.exe
	./test.sh

build/x86 build/x64 lib:
	mkdir -p $@

lib/ArgX32.lib: $(LIB32OBJS) lib
	$(AR) -nologo -out:$@ $(LIB32OBJS)

lib/ArgX64.lib: $(LIB64OBJS) lib
	$(AR) -nologo -out:$@ $(LIB64OBJS)

build/x86/argxtesta.exe: export LIB=$(LIB32)
build/x86/argxtesta.exe: test/argxtest.cpp lib/ArgX32.lib
	$(CL32) $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x86/argxtestw.exe: export LIB=$(LIB32)
build/x86/argxtestw.exe: test/argxtest.cpp lib/ArgX32.lib
	$(CL32) -DUNICODE -D_UNICODE $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x64/argxtesta.exe: export LIB=$(LIB64)
build/x64/argxtesta.exe: test/argxtest.cpp lib/ArgX64.lib
	$(CL64) $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x64/argxtestw.exe: export LIB=$(LIB64)
build/x64/argxtestw.exe: test/argxtest.cpp lib/ArgX64.lib
	$(CL64) -DUNICODE -D_UNICODE $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x86/argxruna.exe: export LIB=$(LIB32)
build/x86/argxruna.exe: test/argxrun.cpp lib/ArgX32.lib
	$(CL32) $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x86/argxrunw.exe: export LIB=$(LIB32)
build/x86/argxrunw.exe: test/argxrun.cpp lib/ArgX32.lib
	$(CL32) -DUNICODE -D_UNICODE $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x64/argxruna.exe: export LIB=$(LIB64)
build/x64/argxruna.exe: test/argxrun.cpp lib/ArgX64.lib
	$(CL64) $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)

build/x64/argxrunw.exe: export LIB=$(LIB64)
build/x64/argxrunw.exe: test/argxrun.cpp lib/ArgX64.lib
	$(CL64) -DUNICODE -D_UNICODE $(CPPFLAGS) -Fe$@ $^ $(TESTLIBS)
