// csp_service_program_interface.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

/*
	多线程   线程同步
*/

//1 CPAcquireContext		SUCCESS
CSPINTERFACE BOOL WINAPI CPAcquireContext(
	__out HCRYPTPROV *phProv,
	__in CHAR *pszContainer,
	__in DWORD dwFlags,
	__in PVTableProvStruc pVTable
)
{
#ifdef DEBUG
	puts("CPAcquireContext");
#endif
	int ret = 0;
	
	//初始化线程同步
	if ((ret = CSP_InitMutex()) != 0) {
		return FALSE;
	}
	__try {
		//线程同步
		CSP_LockMutex();
		LogEntry("CPAcquireContext", "start", 0, 10);

		ret = cpAcquireContextImpl(phProv,pszContainer,dwFlags,pVTable);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally
	{
		//线程同步 结束
		LogEntry("CPAcquireContext", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}

//2 CPGetProvParam			SUCCESS
CSPINTERFACE BOOL WINAPI CPGetProvParam(
	__in HCRYPTPROV hProv,
	__in DWORD dwParam,
	__out BYTE *pbData,
	__inout DWORD *pdwDataLen,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPGetProvParam");
#endif
	int ret = 0;

	__try {
		CSP_LockMutex();
		LogEntry("CPGetProvParam", "start", 0, 10);
		//
		ret = cpGetProvParamImpl( hProv,dwParam,pbData,pdwDataLen,dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally{
		LogEntry("CPGetProvParam", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//3 CPReleaseContext		SUCCESS
CSPINTERFACE BOOL WINAPI CPReleaseContext(
	__in HCRYPTPROV hProv,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPReleaseContext");
#endif
	CSP_LockMutex();
	LogEntry("CPReleaseContext", "start", 0, 10);
	LogEntry("CPReleaseContext", "end", 0, 10);
	CSP_UnlockMutex();
	//结束线程同步
	cpReleaseContextImpl(hProv, dwFlags);
	return TRUE;
}


//4 CPSetProvParam			SUCCESS
CSPINTERFACE BOOL WINAPI CPSetProvParam(
	__in HCRYPTPROV hProv,
	__in DWORD dwParam,
	__in BYTE *pbData,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPSetProvParam");
#endif
	int ret = 0;

	__try {
		CSP_LockMutex();
		LogEntry("CPSetProvParam", "start", 0, 10);

		ret = cpSetProvParamImpl(hProv,dwParam,pbData,dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPSetProvParam", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//5 CPDeriveKey				SUCCESS
CSPINTERFACE BOOL WINAPI CPDeriveKey(
	__in HCRYPTPROV hProv,
	__in ALG_ID Algid,
	__in HCRYPTHASH hBaseData,
	__in DWORD dwFlags,
	__out HCRYPTKEY *phKey
	)
{
	int ret = 0;
#ifdef DEBUG
	puts("CPDeriveKey");
#endif
	
	__try {
		CSP_LockMutex();
		LogEntry("CPDeriveKey", "start", 0, 10);

		//派生密钥
		ret = cpDeriveKeyImpl(hProv, Algid, hBaseData, dwFlags, phKey);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPDeriveKey", "end", 0, 10);
		CSP_UnlockMutex();
	}

	return TRUE;
}


//6 CPDestroyKey			SUCCESS
CSPINTERFACE BOOL WINAPI CPDestroyKey(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPDestroyKey");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPDestroyKey", "start", 0, 10);
	
		ret = cpDestroyKeyImpl( hProv,  hKey);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPDestroyKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//7 CPExportKey				SUCCESS
CSPINTERFACE BOOL WINAPI CPExportKey(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in HCRYPTKEY hPubKey,
	__in DWORD dwBlobType,
	__in DWORD dwFlags,
	__out BYTE *pbData,
	__inout DWORD *pdwDataLen
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPExportKey");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPExportKey", "start", 0, 10);

		//RSA导出DES密钥
		ret = cpExportKeyImpl(hProv, hKey, hPubKey, dwBlobType, dwFlags, pbData, pdwDataLen);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPExportKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//8 CPGenKey				SUCCESS
CSPINTERFACE BOOL WINAPI CPGenKey(
	__in HCRYPTPROV hProv,
	__in ALG_ID Algid,
	__in DWORD dwFlags,
	__out HCRYPTKEY *phKey
	)
{
	int ret = 0;
#ifdef DEBUG
	puts("CPGenKey");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPGenKey", "start", 0, 10);

		//生成密钥
		ret = cpGenKeyImpl(hProv,Algid,dwFlags,phKey);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPGenKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//9 CPGenRandom				SUCCESS
CSPINTERFACE BOOL WINAPI CPGenRandom(
	__in HCRYPTPROV hProv,
	__in DWORD dwLen,
	__inout BYTE *pbBuffer
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPGenRandom");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPGenRandom", "start", 0, 10);
	
		//生成随机数
		ret = cpGenRandomImpl(hProv,dwLen,pbBuffer);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPGenRandom", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//10 CPGetKeyParam			SUCCESS
CSPINTERFACE BOOL WINAPI CPGetKeyParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in DWORD dwParam,
	__out LPBYTE pbData,
	__inout LPDWORD pcbDataLen,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPGetKeyParam");
#endif
	
	__try {
		CSP_LockMutex();
		LogEntry("CPGetKeyParam", "start", 0, 10);
	
		///////
		ret = cpGetKeyParamImpl( hProv,hKey,dwParam,pbData,pcbDataLen,dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPGetKeyParam", "end", 0, 10);
		CSP_UnlockMutex();
	}
	
	return TRUE;
}

//11 CPGetUserKey			SUCCESS
CSPINTERFACE BOOL WINAPI CPGetUserKey(
	__in HCRYPTPROV hProv,
	__in DWORD dwKeySpec,
	__out HCRYPTKEY *phUserKey
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPGetUserKey");
#endif

	__try {
		CSP_LockMutex();
		LogEntry("CPGetUserKey", "start", 0, 10);

		ret = cpGetUserKeyImpl(hProv,dwKeySpec,phUserKey);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPGetUserKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	
	
	return TRUE;
}


//12 CPImportKey			SUCCESS
CSPINTERFACE BOOL WINAPI CPImportKey(
	__in HCRYPTPROV hProv,
	__in const BYTE *pbData,
	__in DWORD dwDataLen,
	__in HCRYPTKEY hPubKey,
	__in DWORD dwFlags,
	__out HCRYPTKEY *phKey
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPImportKey");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPImportKey", "start", 0, 10);

		////
		ret = cpImportKeyImpl(hProv,pbData, dwDataLen, hPubKey, dwFlags,phKey);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPImportKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	
	
	return TRUE;
}


//13 CPSetKeyParam			SUCCESS
CSPINTERFACE BOOL WINAPI CPSetKeyParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in DWORD dwParam,
	__in BYTE *pbData,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPSetKeyParam");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPSetKeyParam", "start", 0, 10);
	
		////
		ret = cpSetKeyParamImpl(hProv,hKey,dwParam,pbData,dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}__finally{
		LogEntry("CPSetKeyParam", "end", 0, 10);
		CSP_UnlockMutex();
	}

	return TRUE;
}


//14 CPDecrypt			SUCCESS
CSPINTERFACE BOOL WINAPI CPDecrypt(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in HCRYPTHASH hHash,
	__in BOOL Final,
	__in DWORD dwFlags,
	__inout BYTE *pbData,
	__inout DWORD *pdwDataLen
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPDecrypt");
#endif

	__try {
		CSP_LockMutex();
		LogEntry("CPDecrypt", "start", 0, 10);

		////
		ret =  cpDecryptImpl(hProv,hKey, hHash, Final,dwFlags,pbData,pdwDataLen);
		if (ret != 0) {
			return FALSE;
		}	
	}
	__finally {
		LogEntry("CPDecrypt", "end", 0, 10);
		CSP_UnlockMutex();
	}
	
	return TRUE;
}


//15 CPEncrypt			SUCCESS
CSPINTERFACE BOOL WINAPI CPEncrypt(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in HCRYPTHASH hHash,
	__in BOOL Final,
	__in DWORD dwFlags,
	__inout BYTE *pbData,
	__inout DWORD *pdwDataLen,
	__in DWORD dwBufLen
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPEncrypt");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPEncrypt", "start", 0, 10);
	
		//容器是否初始化
		ret =  cpEncryptImpl(hProv, hKey, hHash, Final, dwFlags,pbData, pdwDataLen,dwBufLen);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPEncrypt", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//16 CPCreateHash			SUCCESS
CSPINTERFACE BOOL WINAPI CPCreateHash(
	__in HCRYPTPROV hProv,
	__in ALG_ID Algid,
	__in HCRYPTKEY hKey,
	__in DWORD dwFlags,
	__out HCRYPTHASH *phHash
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPCreateHash");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPCreateHash", "start", 0, 10);
	
		////
		ret = cpCreateHashImpl(hProv, Algid,  hKey,  dwFlags, phHash);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPCreateHash", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//17 CPDestroyHash			SUCCESS
CSPINTERFACE BOOL WINAPI CPDestroyHash(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPDestroyHash");
#endif
	__try {
		LogEntry("CPDestroyHash", "start", 0, 10);
		CSP_LockMutex();
		//容器是否初始化
		ret = cpDestroyHashImpl( hProv, hHash);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		CSP_UnlockMutex();
		LogEntry("CPDestroyHash", "end", 0, 10);
	}

	return TRUE;
}


//18 CPDuplicateHash 附加函数	SUCCESS
CSPINTERFACE BOOL WINAPI CPDuplicateHash(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__reserved DWORD *pdwReserved,
	__in DWORD dwFlags,
	__out HCRYPTHASH *phHash
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPDuplicateHash");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPDuplicateHash", "start", 0, 10);
		
		ret = cpDuplicateHashImpl( hProv,  hHash, pdwReserved,  dwFlags, phHash);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPDuplicateHash", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//19 CPGetHashParam			SUCCESS
CSPINTERFACE BOOL WINAPI CPGetHashParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in DWORD dwParam,
	__out BYTE *pbData,
	__inout DWORD *pdwDataLen,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPGetHashParam");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPGetHashParam", "start", 0, 10);
	
		////
		ret =  cpGetHashParamImpl(hProv, hHash,  dwParam, pbData, pdwDataLen, dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally{
		LogEntry("CPGetHashParam", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//20 CPHashData			SUCCESS
CSPINTERFACE BOOL WINAPI CPHashData(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in const BYTE *pbData,
	__in DWORD dwDataLen,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPHashData");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPHashData", "start", 0, 10);
		
		////
		ret = cpHashDataImpl( hProv,  hHash, pbData,  dwDataLen,  dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPHashData", "end", 0, 10);
		CSP_UnlockMutex();
	}

	return TRUE;
}


//21 CPSetHashParam			SUCCESS
CSPINTERFACE BOOL WINAPI CPSetHashParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in DWORD dwParam,
	__in BYTE *pbData,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPSetHashParam");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPSetHashParam", "start", 0, 10);
		
		////
		ret = cpSetHashParamImpl( hProv,  hHash,  dwParam, pbData, dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPSetHashParam", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//22 CPSignHash			 SUCCESS
CSPINTERFACE BOOL WINAPI CPSignHash(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in DWORD dwKeySpec,
	__in LPCWSTR sDescription,
	__in DWORD dwFlags,
	__out BYTE *pbSignature,
	__inout DWORD *pdwSigLen
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPSignHash");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPSignHash", "start", 0, 10);
		
		//
		ret = cpSignHashImpl( hProv,  hHash,  dwKeySpec,  sDescription,  dwFlags, pbSignature, pdwSigLen);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPSignHash", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//23 CPVerifySignature			SUCCESS
CSPINTERFACE BOOL WINAPI CPVerifySignature(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in const BYTE *pbSignature,
	__in DWORD dwSigLen,
	__in HCRYPTKEY hPubKey,
	__in LPCWSTR sDescription,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPVerifySignature");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPVerifySignature", "start", 0, 10);
	
		ret = cpVerifySignatureImpl( hProv,  hHash, pbSignature,  dwSigLen,  hPubKey,  sDescription,  dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPVerifySignature", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//24 CPDuplicateKey 附加函数	SUCCESS
CSPINTERFACE BOOL WINAPI CPDuplicateKey(
	__in HCRYPTPROV hUID,
	__in HCRYPTKEY hKey,
	__in DWORD *pdwReserved,
	__in DWORD dwFlags,
	__out HCRYPTKEY *phKey
	)
{
	int ret = 0;
#ifdef DEBUG
	puts("CPDuplicateKey");
#endif
	__try {
		CSP_LockMutex();
		LogEntry("CPDuplicateKey", "start", 0, 10);
	
		ret = cpDuplicateKeyImpl( hUID,  hKey,  pdwReserved,  dwFlags,  phKey);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPDuplicateKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}


//25 CPHashSessionKey		SUCCESS
CSPINTERFACE BOOL WINAPI CPHashSessionKey(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in HCRYPTKEY hKey,
	__in DWORD dwFlags
	)
{
	int ret = 0;

#ifdef DEBUG
	puts("CPHashSessionKey");
#endif

	__try {
		CSP_LockMutex();
		LogEntry("CPHashSessionKey", "start", 0, 10);
		
		/////
		ret = cpHashSessionKeyImpl( hProv,  hHash,  hKey,  dwFlags);
		if (ret != 0) {
			return FALSE;
		}
	}
	__finally {
		LogEntry("CPHashSessionKey", "end", 0, 10);
		CSP_UnlockMutex();
	}
	return TRUE;
}




