#
#  ArgX - Better command line processing for Windows.
#
#  Copyright (c) 2019 Alastair J. Houghton.
#

# This Makefile sets up variables so we can build things using MSVC

VSWHERE:="${PROGRAMFILES}/Microsoft Visual Studio/Installer/vswhere.exe"

# First, locate the Visual Studio tools themselves
VS_ROOT:=$(shell ${VSWHERE} -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | cygpath -f -)
VS_VERSION:=$(shell cat "${VS_ROOT}/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt")

# Next, find the Windows 10 SDK
SDK_INFO:=$(shell reg query 'HKLM\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0' 2>/dev/null | tr -d '\r' | tr '\n' '*')
ifndef SDK_INFO
  SDK_INFO:=$(shell reg query 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows\v10.0' 2>/dev/null | tr -d '\r' | tr '\n' '*')
endif
SDK_ROOT:=$(shell echo "${SDK_INFO}" | grep -o 'InstallationFolder\s\+[^*]\+' | sed 's/.*\s\+REG_SZ\s\+\(.*\)/\1/g' | cygpath -f -)
SDK_NAME:=$(shell echo "${SDK_INFO}" | grep -o 'ProductName\s\+[^*]\+' | sed 's/.*\s\+REG_SZ\s\+\(.*\)/\1/g')
SDK_VERSION:=$(shell echo "${SDK_INFO}" | grep -o 'ProductVersion\s\+[^*]\+' | sed 's/.*\s\+REG_SZ\s\+\(.*\)/\1/g')
SDK_VERSION:=${SDK_VERSION}.0

# Work out the toolchain paths
VS_BIN_ROOT:=${VS_ROOT}/VC/Tools/MSVC/${VS_VERSION}/bin
VS_BIN32:=${VS_BIN_ROOT}/HostX64/x86
VS_BIN64:=${VS_BIN_ROOT}/HostX64/x64

# Work out the library and include paths
VS_INCLUDE:=$(shell echo "${VS_ROOT}/VC/Tools/MSVC/${VS_VERSION}/include" | cygpath -w -f - | sed 's/\s\+$$//g')
VS_LIB_ROOT:=$(shell echo "${VS_ROOT}/VC/Tools/MSVC/${VS_VERSION}/lib" | cygpath -w -f -)
VS_LIB32:=${VS_LIB_ROOT}\x86
VS_LIB64:=${VS_LIB_ROOT}\x64

SDK_INCLUDE_ROOT:=$(shell echo "${SDK_ROOT}/Include/${SDK_VERSION}" | cygpath -w -f -)
SDK_INCLUDE:=${SDK_INCLUDE_ROOT}\um;${SDK_INCLUDE_ROOT}\ucrt;${SDK_INCLUDE_ROOT}\shared

SDK_LIB_ROOT:=$(shell echo "${SDK_ROOT}/Lib/${SDK_VERSION}" | cygpath -w -f -)
SDK_LIB32:=${SDK_LIB_ROOT}\um\x86;${SDK_LIB_ROOT}\ucrt\x86
SDK_LIB64:=${SDK_LIB_ROOT}\um\x64;${SDK_LIB_ROOT}\ucrt\x64

INCLUDE:=${VS_INCLUDE};${SDK_INCLUDE}
LIB32:=${VS_LIB32};${SDK_LIB32}
LIB64:=${VS_LIB64};${SDK_LIB64}

export INCLUDE
export LIB:=${LIB32}

# Set the paths of some tools
CL32:="${VS_BIN32}/CL.exe"
CL64:="${VS_BIN64}/CL.exe"
AR:="${VS_BIN64}/LIB.exe"
LINK:="${VS_BIN64}/LINK.exe"

$(info Using Visual Studio ${VS_VERSION} with Windows SDK '${SDK_VERSION}')
$(info  )
