#include "stdafx.h"
#include "regedit.h"

char csRun[] = "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\GMNCSP";

char * getCsRun(void){
	return csRun;
}

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
) {
	return RegCreateKeyExA( hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,
							lpSecurityAttributes,phkResult,lpdwDisposition);
}

LONG GMN_RegOpenKeyEx(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
) {
	return RegOpenKeyExA(
	hKey,lpSubKey,
	ulOptions,samDesired,phkResult);
}

LONG GMN_RegCloseKey(
	HKEY hKey
) {
	return RegCloseKey(hKey);
}

LONG GMN_RegDeleteValue(
	HKEY hKey,
	LPCSTR lpValueName
) {
	return RegDeleteValueA( hKey, lpValueName);
}

LONG GMN_RegSetValueEx(
	HKEY hKey,
	LPCSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	BYTE * lpData,
	DWORD cbData
) {
	return RegSetValueExA(
		hKey,
		lpValueName,
		Reserved,
		dwType,
		lpData,
		cbData);
}

LONG GMN_RegQueryValueEx(
	 HKEY hKey,
	 LPCSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
) {
	return RegQueryValueExA(
		 hKey,
		 lpValueName,
		 lpReserved,
		 lpType,
		 lpData,
		 lpcbData);
}

LONG GMN_RegOpen(HKEY * phKey) {
	
	long lRet;
	DWORD state;

	lRet = GMN_RegOpenKeyEx(HKEY_LOCAL_MACHINE, getCsRun(), 0, KEY_ALL_ACCESS, phKey);
	if (lRet != ERROR_SUCCESS) {
		lRet = GMN_RegCreateKeyEx(HKEY_LOCAL_MACHINE, getCsRun(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, phKey, &state);
	}
	return lRet;
}