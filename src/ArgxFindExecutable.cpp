/*
 * ArgX - Better command line processing for Windows.
 *
 * Copyright (c) 2019 Alastair J. Houghton.
 *
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <shlwapi.h>
#include <limits.h>

#include "ArgX.h"

namespace {
  class StringException {
  public:
    StringException() {}
  };

  class String {
  public:
    String() : m_count(0), m_capacity(0), m_pszData(NULL) {}
    String(SIZE_T capacity) : m_count(0), m_capacity(capacity) {
      m_pszData = (LPWSTR)LocalAlloc(LMEM_FIXED, capacity * sizeof(WCHAR));
      if (!m_pszData)
	throw StringException();
    }
    String(LPCWSTR psz) : m_count(0), m_capacity(0), m_pszData(NULL) {
      append(psz);
    }
    String(const WCHAR* psz, SIZE_T count)
      : m_count(0), m_capacity(0), m_pszData(NULL) {
      append(psz, count);
    }
    String(const String& other)
      : m_count(0), m_capacity(0), m_pszData(NULL) {
      append(other);
    }
    ~String() {
      if (m_pszData)
	LocalFree((HLOCAL)m_pszData);
    }

    String& assign(const WCHAR* psz, SIZE_T len) {
      m_count = 0;
      return append(psz, len);
    }

    String& assign(LPCWSTR psz) {
      return assign(psz, lstrlenW(psz));
    }

    String& assign(const String& other) {
      return assign(other.m_pszData, other.m_count);
    }

    String& assign(WCHAR ch) {
      return assign(&ch, 1);
    }

    String& assign(char ch) {
      WCHAR wch = ch;
      return assign(&wch, 1);
    }

    String& append(const WCHAR* psz, SIZE_T len) {
      ensure(len);
      CopyMemory(m_pszData + m_count, psz, len * sizeof(WCHAR));
      m_count += len;

      return *this;
    }

    String& append(LPCWSTR psz) {
      return append(psz, lstrlenW(psz));
    }

    String& append(const String& other) {
      return append(other.m_pszData, other.m_count);
    }

    String& append(WCHAR ch) {
      return append(&ch, 1);
    }

    String& append(char ch) {
      WCHAR wch = ch;
      return append(&wch, 1);
    }

    LPWSTR take() {
      shrink();
      LPWSTR result = m_pszData;
      m_count = m_capacity = 0;
      m_pszData = NULL;
      return result;
    }

    DWORD dwordCapacity() const {
      if (m_capacity > ~(DWORD)0)
	return ~(DWORD)0;
      return (DWORD)m_capacity;
    }

    void ensure(SIZE_T required) {
      if (m_capacity - m_count < required) {
	SIZE_T newCapacity = (m_count + required + 255) & ~255;
	LPWSTR pszData;

	if (!m_pszData)
	  pszData = (LPWSTR)LocalAlloc(LMEM_FIXED, newCapacity * sizeof(WCHAR));
	else {
	  pszData = (LPWSTR)LocalReAlloc((HLOCAL)m_pszData,
					 newCapacity * sizeof(WCHAR), 0);
	}

	if (!pszData)
	  throw StringException();

	m_pszData = pszData;
	m_capacity = newCapacity;
      }
    }

    void shrink() {
      if (m_capacity > m_count) {
	LPWSTR pszData = (LPWSTR)LocalReAlloc((HLOCAL)m_pszData,
					      m_count * sizeof(WCHAR), 0);

	if (pszData) {
	  m_pszData = pszData;
	  m_capacity = m_count;
	}
      }
    }

  public:
    SIZE_T m_count;
    SIZE_T m_capacity;
    LPWSTR m_pszData;
  };
}

// Look up the name of the executable to start based on the (given)
// first argument.  The lookup proceeds in the following order:
//
// 1. The directory from which the application was loaded.
// 2. The current directory.
// 3. The directory returned by GetSystemDirectory().
// 4. The 16-bit Windows directory (GetSystemDirectory()/../System).
// 5. The directory returned by GetWindowsDirectory().
// 6. The directories listed in the PATH environment variable.
//
// Additionally, if the argument has no extension, .exe will be
// appended.

LPWSTR ARGXAPI
ArgxFindExecutableW(LPCWSTR lpszArgv0)
{
  SIZE_T len = lstrlenW(lpszArgv0);
  LPCWSTR psz = lpszArgv0 + len;
  BOOL hasExtension = FALSE, hasPath = FALSE;

  // Check for an extension or a path
  while (psz != lpszArgv0) {
    WCHAR ch = *--psz;

    if (ch == '\\' || ch == '/' || ch == ':') {
      hasPath = TRUE;
      break;
    }
    if (ch == '.') {
      hasExtension = TRUE;
    }
  }

  // If it has a path, return a copy of the string as-is
  if (hasPath) {
    LPWSTR pszResult = (LPWSTR)LocalAlloc(LMEM_FIXED, len + 1);
    CopyMemory(pszResult, lpszArgv0, (len + 1) * sizeof(WCHAR));
    return pszResult;
  }

  try {
    DWORD dwRet;
    String exeName(lpszArgv0);

    if (!hasExtension)
      exeName.append(L".exe");

    // 1. The directory from which the application was loaded.
    String path(32768);

    dwRet = GetModuleFileNameW(NULL,
			       path.m_pszData,
			       path.dwordCapacity());
    if (dwRet) {
      // dwRet INCLUDES the NUL
      path.m_count = dwRet - 1;

      LPWSTR pszPath = path.m_pszData + path.m_count;
      BOOL found = FALSE;
      while (pszPath > path.m_pszData) {
	WCHAR ch = *--pszPath;
	if (ch == L'\\' || ch == L'/') {
	  path.m_count = pszPath - path.m_pszData + 1;
	  found = TRUE;
	  break;
	}
      }

      if (found) {
	path.append(exeName);
	path.append('\0');
	if (PathFileExistsW(path.m_pszData))
	  return path.take();
      }
    }

    // 2. The current directory.
    dwRet = GetCurrentDirectoryW(path.dwordCapacity(),
				 path.m_pszData);

    if (dwRet) {
      // In this case, dwRet DOES NOT include the NUL
      path.m_count = dwRet;

      WCHAR ch = path.m_pszData[path.m_count - 1];
      if (ch != '\\' && ch != '/')
	path.append('\\');

      path.append(exeName);
      path.append('\0');
      if (PathFileExistsW(path.m_pszData))
	return path.take();
    }

    // 3. The directory returned by GetSystemDirectory().
    dwRet = GetSystemDirectoryW(path.m_pszData,
				path.dwordCapacity());

    if (dwRet) {
      // dwRet DOES NOT include the NUL
      path.m_count = dwRet;

      WCHAR ch = path.m_pszData[path.m_count - 1];
      if (ch != '\\' && ch != '/')
	path.append('\\');

      path.append(exeName);
      path.append('\0');
      if (PathFileExistsW(path.m_pszData))
	return path.take();
    }

    // 4. The 16-bit Windows directory (GetSystemDirectory()/../System).
    if (dwRet) {
      path.m_count = dwRet;

      LPWSTR pszPath = path.m_pszData + path.m_count;
      BOOL found = FALSE;
      while (pszPath > path.m_pszData) {
	WCHAR ch = *--pszPath;
	if (ch == L'\\' || ch == L'/') {
	  path.m_count = pszPath - path.m_pszData + 1;
	  found = TRUE;
	  break;
	}
      }

      if (found) {
	path.append(L"System\\");
	path.append(exeName);
	path.append('\0');
	if (PathFileExistsW(path.m_pszData))
	  return path.take();
      }
    }

    // 5. The directory returned by GetWindowsDirectory().
    dwRet = GetWindowsDirectoryW(path.m_pszData,
				 path.dwordCapacity());

    if (dwRet) {
      // dwRet DOES NOT include the NUL
      path.m_count = dwRet;

      WCHAR ch = path.m_pszData[path.m_count - 1];
      if (ch != '\\' && ch != '/')
	path.append('\\');

      path.append(exeName);
      path.append('\0');
      if (PathFileExistsW(path.m_pszData))
	return path.take();
    }

    // 6. The directories listed in the PATH environment variable
    String pathList(32768);

    dwRet = GetEnvironmentVariableW(L"PATH",
				    pathList.m_pszData,
				    pathList.dwordCapacity());

    if (dwRet > pathList.m_capacity) {
      pathList.ensure(dwRet);
      dwRet = GetEnvironmentVariableW(L"PATH",
				      pathList.m_pszData,
				      pathList.dwordCapacity());

      if (dwRet > pathList.m_capacity)
	dwRet = 0;
    }

    if (dwRet) {
      LPWSTR pszList = pathList.m_pszData;
      LPWSTR pszStart = pszList;
      BOOL done = FALSE;

      while (!done) {
	WCHAR ch = *pszList;

	if (ch == L';' || !ch) {
	  if (!ch)
	    done = TRUE;

	  *pszList = L'\0';
	  path.assign(pszStart);

	  ch = path.m_pszData[path.m_count - 1];
	  if (ch != '\\' && ch != '/')
	    path.append('\\');

	  path.append(exeName);
	  path.append('\0');
	  if (PathFileExistsW(path.m_pszData))
	    return path.take();

	  pszStart = ++pszList;
	} else {
	  ++pszList;
	}
      }
    }
  } catch (const StringException &) {
    return NULL;
  }

  return NULL;
}
