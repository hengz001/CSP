#ifndef REGEDIT_H
#define REGEDIT_H

#include <Windows.h>

char * getCsRun();

LONG GMN_RegCreateKeyEx(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD Reserved,
	LPSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
);

LONG GMN_RegOpenKeyEx(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
);

LONG GMN_RegCloseKey(
	HKEY hKey
);

LONG GMN_RegDeleteValue(
	HKEY hKey,
	LPCSTR lpValueName
);

LONG GMN_RegSetValueEx(
	HKEY hKey,
	LPCSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	BYTE * lpData,
	DWORD cbData
);

LONG GMN_RegQueryValueEx(
	HKEY hKey,
	LPCSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
);

LONG GMN_RegOpen(HKEY * phKey);

#endif
