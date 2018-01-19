// csp_service_program_interface.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

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
	int rv;

	//初始化线程同步
	if ((rv = CSP_InitMutex()) != 0){
		CSP_UnlockMutex();
		return FALSE;
	}
	CSP_LockMutex();

	//加载配置文件
	if (initCSP()<0){
		CSP_UnlockMutex();
		return FALSE;
	}

	LogEntry("CPAcquireContext", "start", 0, 10);

	//加密机状态
	if (testSjl22() != 0){
		CSP_UnlockMutex();
		return FALSE;
	}

	//返回密钥容器句柄
	*phProv = getMutexFlag();

	CSP_UnlockMutex();
	LogEntry("CPAcquireContext", "end", 0, 10);
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
	LONG lRet;
	HKEY hKey;

	LogEntry("CPGetProvParam", "start", 0, 10);
	
	CSP_LockMutex();

	//容器是否初始化
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	//获取注册表属性
	lRet = GMN_RegOpen(&hKey);
	if (ERROR_SUCCESS != lRet) {
		VarLogEntry(" GMN_RegOpen", "error: %u", -1, 0, lRet);
		CSP_UnlockMutex();
		return FALSE;
	}

	//获取属性
	lRet = GMN_RegQueryValueEx(hKey,(CHAR*)dwParam, 0, &dwFlags, pbData, pdwDataLen);
	if (ERROR_SUCCESS != lRet) {
		VarLogEntry(" GMN_RegQueryValueEx", "error: %u", -1, 0, lRet);
		VarLogEntry(" GMN_RegQueryValueEx", "key: %s", -1, 0,
				(CHAR*)dwParam);
		CSP_UnlockMutex();
		return FALSE;
	}

	CSP_UnlockMutex();
	LogEntry("CPGetProvParam", "end", 0, 10);
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
	LogEntry("CPReleaseContext", "start", 0, 10);
	CSP_LockMutex();
	CSP_UnlockMutex();
	//结束线程同步
	CSP_Destroy_Mutex();
	LogEntry("CPReleaseContext", "end", 0, 10);
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
	LONG lRet;
	HKEY hKey;
	
	LogEntry("CPSetProvParam", "start", 0, 10);
	CSP_LockMutex();

	//容器是否初始化
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	//获取注册表属性
	lRet = GMN_RegOpen(&hKey);
	if (ERROR_SUCCESS != lRet) {
		VarLogEntry(" GMN_RegOpen", "error: %u", -1, 0, lRet);
		CSP_UnlockMutex();
		return FALSE;
	}

	
	//设置注册表属性
	lRet = GMN_RegSetValueEx(hKey, (LPCSTR)dwParam, 0, 
							 (NULL == dwFlags?REG_SZ: dwFlags), 
								 pbData, strlen((char*)pbData));
	if (ERROR_SUCCESS != lRet) {
		VarLogEntry(" GMN_RegSetValueEx", "error: %u", -1, 0, lRet);
		CSP_UnlockMutex();
		return FALSE;
	}

	CSP_UnlockMutex();
	LogEntry("CPSetProvParam", "end", 0, 10);
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
#ifdef DEBUG
	puts("CPDeriveKey");
#endif
	LogEntry("CPDeriveKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	///////////////////////////
	int timeout = 0;
	int comid;
	int ret = 0;
	CHAR cKey[256];
	UCHAR deriveKey[256];
	UCHAR checkValue[256];
	HKEY_Z *hKey_z = (HKEY_Z*)phKey;
	char *key = (CHAR*)hKey_z->key;
	int algo = Algid;
	char *data = (char*)hBaseData;
	int dataLen = strlen(data);
	int keyLen = strlen(key)/2;
	int derivationmode = 0;
	int encmode = 0;
	char deriveKeyType[] = ZMK_TYPE;
	char derivationKeyType[] = ZMK_TYPE;
	char *iv = NULL;
	int deriveKeyLen;
	HKEY_Z *hKey_deri;
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
	if (comid<0) {
		VarLogEntry(" InitHsmDevice", "connect error", comid, 0);
		CSP_UnlockMutex();
		return FALSE;
	}

	PackBCD(key, (unsigned char*)cKey, strlen(key));
	__try {
		ret = derivatekey(comid, 0, NULL, algo, derivationmode, encmode, deriveKeyType, derivationKeyType, keyLen, cKey, dataLen, iv, data, 0, NULL, NULL, (char*)deriveKey, (char*)checkValue);
		if (ret<0) {
			VarLogEntry("derivatekey", "error", ret, 0);
			CSP_UnlockMutex();
			return FALSE;
		}
		deriveKeyLen = strlen((CHAR*)deriveKey);
		
		
		hKey_deri = (HKEY_Z *)malloc(1);
		if (NULL == hKey_deri) {
			VarLogEntry("CPDeriveKey", "memory error", -1, 0);
			CSP_UnlockMutex();
			return FALSE;
		}

		hKey_deri->len = deriveKeyLen;
		memcpy(hKey_deri->key,deriveKey,deriveKeyLen);
		memcpy(hKey_deri->key, checkValue,strlen((CHAR*)checkValue));
		*phKey = (LONG)hKey_deri;
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	//////////////////////////
	
	CSP_UnlockMutex();
	LogEntry("CPDeriveKey", "end", 0, 10);
	return TRUE;
}


//6 CPDestroyKey			SUCCESS
CSPINTERFACE BOOL WINAPI CPDestroyKey(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey
	)
{
#ifdef DEBUG
	puts("CPDestroyKey");
#endif
	LogEntry("CPDestroyKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	if (NULL != hKey) {
		free((void*)hKey);
	}
	
	CSP_UnlockMutex();
	LogEntry("CPDestroyKey", "end", 0, 10);
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
	int ret;
	UCHAR data[4096],*p;
	int data_length;

#ifdef DEBUG
	puts("CPExportKey");
#endif
	LogEntry("CPExportKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	ret = exportrsadeskeyImpl(hKey,hPubKey,data,&data_length);
	if (ret<0|| data_length<0) {
		VarLogEntry("CPExportKey", "exportrsadeskeyImpl error", ret, 0);
		CSP_UnlockMutex();
		return FALSE;
	}
	memcpy(pbData,data,data_length);
	*pdwDataLen = data_length;

	CSP_UnlockMutex();
	LogEntry("CPExportKey", "end", 0, 10);
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
#ifdef DEBUG
	puts("CPGenKey");
#endif
	int timeout = 0;
	int comid;
	int ret;
	char key[255];
	char checkValue[6+1];
	HPKEY_Z *pKey;
	HKEY_Z *hKey;

	LogEntry("CPGenKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	//////////////////////////// DES
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
	if (comid<0) {
		VarLogEntry(" InitHsmDevice", "connect error", comid, 0);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	__try {
		switch (Algid)
		{
		case ALGO_DESTDES:
			ret = generateKey(comid, 0, NULL,0, 0, ZMK_TYPE, 'X', key, checkValue);
			if (ret<0) {
				VarLogEntry(" CPGenKey", "error", ret, 0);
				CSP_UnlockMutex();
				return FALSE;
			}
			hKey = (HKEY_Z*)malloc(1);
			if (NULL == hKey) {
				VarLogEntry(" CPGenKey", "memory error", -1, 0);
				CSP_UnlockMutex();
				return FALSE;
			}
			hKey->len = strlen(key);
			memcpy(hKey->key,key,hKey->len);
			memcpy(hKey->cv, checkValue,strlen(checkValue));
			*phKey = (LONG)hKey;
			break;
		case SIG_ALGO_RSA:
			pKey = (HPKEY_Z*)malloc(1);
			if (NULL == pKey) {
				VarLogEntry("CPGenKey", "memory error", -1, 0);
				CSP_UnlockMutex();
				return FALSE;
			}
			ret = genrsakeyImpl(dwFlags, pKey, comid);
			if (ret < 0) {
				VarLogEntry("genrsakeyImpl", "error", ret, 0);
				CSP_UnlockMutex();
				free(pKey);
				return FALSE;
			}
			*phKey = (LONG)pKey;
			break;
		default:
			VarLogEntry(" CPGenKey", "Algid error", Algid, 0);
			CSP_UnlockMutex();
			return FALSE;
		}
	}
	__finally {
		CloseHsmDevice(comid);
	}
	///////////////////////////
	
	CSP_UnlockMutex();
	LogEntry("CPGenKey", "end", 0, 10);
	return TRUE;
}


//9 CPGenRandom				SUCCESS
CSPINTERFACE BOOL WINAPI CPGenRandom(
	__in HCRYPTPROV hProv,
	__in DWORD dwLen,
	__inout BYTE *pbBuffer
	)
{
#ifdef DEBUG
	puts("CPGenRandom");
#endif
	int timeout = 0;
	int comid;
	int ret;

	LogEntry("CPGenRandom", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	////////////////////////////
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
	if (comid<0) {
		VarLogEntry(" InitHsmDevice", "connect error",comid, 0);
		CSP_UnlockMutex();
		return FALSE;
	}

	__try {
		ret = genrandom(comid, 0, NULL, dwLen, pbBuffer);
		if (ret<0) {
			VarLogEntry(" genrandom", "error", ret, 0 );
			CSP_UnlockMutex();
			return FALSE;
		}
	}
	__finally {
		CloseHsmDevice(comid);
	}
	///////////////////////////
	
	CSP_UnlockMutex();
	LogEntry("CPGenRandom", "end", 0, 10);
	return TRUE;
}


//10 CPGetKeyParam		
CSPINTERFACE BOOL WINAPI CPGetKeyParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in DWORD dwParam,
	__out LPBYTE pbData,
	__inout LPDWORD pcbDataLen,
	__in DWORD dwFlags
	)
{
	int len;

#ifdef DEBUG
	puts("CPGetKeyParam");
#endif
	LogEntry("CPGetKeyParam", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	/*
	KP_ALGID 表示返回密钥的算法标识
	KP_BLOCKLEN表示返回密钥的算法数据块长度
	KP_KEYLEN表示返回密钥的长度
	KP_SALT 表示返回密钥的盐值
	KP_PERMISSIONS 表示返回密钥的访问权限
	KP_IV表示返回算法的初始向量
	KP_PADDING 表示返回算法的填充方式
	KP_MODE 表示返回算法的加密模式
	KP_MODE_BITS表示返回算法的加密模式的反馈位数
	KP_EFFECTIVE_KEYLEN 表示返回密钥的有效长度
	*/
	/////////////////////////////////////////////
	switch (dwParam)
	{
	case KP_ALGID:
		break;
	case KP_BLOCKLEN:
		break;
	case KP_KEYLEN:
		break;
	case KP_SALT:
		break;
	case KP_PERMISSIONS:
		break;
	case KP_IV:
		break;
	case KP_PADDING:
		break;
	case KP_MODE:
		break;
	case KP_MODE_BITS:
		break;
	case KP_EFFECTIVE_KEYLEN:
		break;
	default:
		VarLogEntry(" CPGetKeyParam", "dwParam error", dwParam, 0);
		CSP_UnlockMutex();
		return FALSE;
	}

	CSP_UnlockMutex();
	LogEntry("CPGetKeyParam", "end", 0, 10);

	return TRUE;
}

//11 CPGetUserKey
CSPINTERFACE BOOL WINAPI CPGetUserKey(
	__in HCRYPTPROV hProv,
	__in DWORD dwKeySpec,
	__out HCRYPTKEY *phUserKey
	)
{
#ifdef DEBUG
	puts("CPGetUserKey");
#endif
	LogEntry("CPGetUserKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	// dwKeySpec phUserKey 根据密钥属性获取密钥句柄
	if (dwKeySpec) {
		*phUserKey = NULL;
	}
	
	CSP_UnlockMutex();
	LogEntry("CPGetUserKey", "end", 0, 10);
	return TRUE;
}


//12 CPImportKey		SUCCESS
CSPINTERFACE BOOL WINAPI CPImportKey(
	__in HCRYPTPROV hProv,
	__in const BYTE *pbData,
	__in DWORD dwDataLen,
	__in HCRYPTKEY hPubKey,
	__in DWORD dwFlags,
	__out HCRYPTKEY *phKey
	)
{
	HPKEY_Z * pKey;
	HKEY_Z * hKey;
	UCHAR wkLmk[255]; 
	int keylen;
	int ret;
	UCHAR cv[64];

#ifdef DEBUG
	puts("CPImportKey");
#endif
	LogEntry("CPImportKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	pKey = (HPKEY_Z*)hPubKey;
	ret = importrsadeskeyImpl((UCHAR *)pbData, dwDataLen, pKey->pvKey, pKey->pvLen,wkLmk, &keylen, cv);
	if (ret != 0) {
		VarLogEntry(" importrsadeskeyImplvoid", "error",ret, 0);
		CSP_UnlockMutex();
		return FALSE;
	}
	hKey = (HKEY_Z *)malloc(1);
	if (NULL == hKey) {
		VarLogEntry(" CPImportKey", "memory error", -1, 0);
		CSP_UnlockMutex();
		return FALSE;
	}

	hKey->len = keylen;
	memcpy(hKey->key, wkLmk, keylen);
	memcpy(hKey->cv,cv,strlen((CHAR*)cv));

	*phKey = (LONG)hKey;
	CSP_UnlockMutex();
	LogEntry("CPImportKey", "end", 0, 10);
	return TRUE;
}


//13 CPSetKeyParam
CSPINTERFACE BOOL WINAPI CPSetKeyParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in DWORD dwParam,
	__in BYTE *pbData,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPSetKeyParam");
#endif
	LogEntry("CPSetKeyParam", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	switch (dwParam)
	{
	case KP_ALGID:
		break;
	case KP_BLOCKLEN:
		break;
	case KP_KEYLEN:
		break;
	case KP_SALT:
		break;
	case KP_PERMISSIONS:
		break;
	case KP_IV:
		break;
	case KP_PADDING:
		break;
	case KP_MODE:
		break;
	case KP_MODE_BITS:
		break;
	case KP_EFFECTIVE_KEYLEN:
		break;
	default:
		VarLogEntry(" CPGetKeyParam", "dwParam error", dwParam, 0);
		CSP_UnlockMutex();
		return FALSE;
	}


	CSP_UnlockMutex();
	LogEntry("CPSetKeyParam", "end", 0, 10);
	return TRUE;
}


//14 CPDecrypt			ACTION
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
#ifdef DEBUG
	puts("CPDecrypt");
#endif
	LogEntry("CPDecrypt", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	//加解密模型 后期需修改参数
	int encryptDecryptImpl();
	
	CSP_UnlockMutex();
	LogEntry("CPDecrypt", "end", 0, 10);
	return TRUE;
}


//15 CPEncrypt			ACTION
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
#ifdef DEBUG
	puts("CPEncrypt");
#endif
	LogEntry("CPEncrypt", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	//加解密模型 后期需修改参数
	int encryptDecryptImpl();
	
	CSP_UnlockMutex();
	LogEntry("CPEncrypt", "end", 0, 10);
	return TRUE;
}


//16 CPCreateHash		ACTION
CSPINTERFACE BOOL WINAPI CPCreateHash(
	__in HCRYPTPROV hProv,
	__in ALG_ID Algid,
	__in HCRYPTKEY hKey,
	__in DWORD dwFlags,
	__out HCRYPTHASH *phHasg
	)
{
#ifdef DEBUG
	puts("CPCreateHash");
#endif
	LogEntry("CPCreateHash", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	//函数模型 需修改参数
	genhashImpl();

	CSP_UnlockMutex();
	LogEntry("CPCreateHash", "end", 0, 10);
	return TRUE;
}


//17 CPDestroyHash			SUCCESS
CSPINTERFACE BOOL WINAPI CPDestroyHash(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash
	)
{
#ifdef DEBUG
	puts("CPDestroyHash");
#endif
	LogEntry("CPDestroyHash", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	if (NULL != hHash) {
		free((void *)hHash);
	}
	
	CSP_UnlockMutex();
	LogEntry("CPDestroyHash", "end", 0, 10);
	return TRUE;
}


//18 CPDuplicateHash 附加函数
CSPINTERFACE BOOL WINAPI CPDuplicateHash(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__reserved DWORD *pdwReserved,
	__in DWORD dwFlags,
	__out HCRYPTHASH *phHash
	)
{
#ifdef DEBUG
	puts("CPDuplicateHash");
#endif
	LogEntry("CPDuplicateHash", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	CSP_UnlockMutex();
	LogEntry("CPDuplicateHash", "end", 0, 10);
	return TRUE;
}


//19 CPGetHashParam
CSPINTERFACE BOOL WINAPI CPGetHashParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in DWORD dwParam,
	__out BYTE *pbData,
	__inout DWORD *pdwDataLen,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPGetHashParam");
#endif
	LogEntry("CPGetHashParam", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	CSP_UnlockMutex();
	LogEntry("CPGetHashParam", "end", 0, 10);

	return TRUE;
}


//20 CPHashData			ACTION
CSPINTERFACE BOOL WINAPI CPHashData(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in const BYTE *pbData,
	__in DWORD dwDataLen,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPHashData");
#endif
	LogEntry("CPHashData", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	//函数模型 需修改参数
	genhashImpl();

	CSP_UnlockMutex();
	LogEntry("CPHashData", "end", 0, 10);

	return TRUE;
}


//21 CPSetHashParam
CSPINTERFACE BOOL WINAPI CPSetHashParam(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in DWORD dwParam,
	__in BYTE *pbData,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPSetHashParam");
#endif
	LogEntry("CPSetHashParam", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	CSP_UnlockMutex();
	LogEntry("CPSetHashParam", "end", 0, 10);

	return TRUE;
}


//22 CPSignHash		ACTION
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
#ifdef DEBUG
	puts("CPSignHash");
#endif
	LogEntry("CPSignHash", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	//需完善
	int rsaprisignImpl();
	
	CSP_UnlockMutex();
	LogEntry("CPSignHash", "end", 0, 10);
	return TRUE;
}


//23 CPVerifySignature		ACTION
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
#ifdef DEBUG
	puts("CPVerifySignature");
#endif
	LogEntry("CPVerifySignature", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	//需完善
	int rsapubverifyImpl();

	CSP_UnlockMutex();
	LogEntry("CPVerifySignature", "end", 0, 10);
	return TRUE;
}


//24 CPDuplicateKey 附加函数
CSPINTERFACE BOOL WINAPI CPDuplicateKey(
	__in HCRYPTPROV hProv,
	__in HCRYPTKEY hKey,
	__in DWORD *pdwReserved,
	__in DWORD dwFlags,
	__out HCRYPTKEY *phKey
	)
{
#ifdef DEBUG
	puts("CPDuplicateKey");
#endif
	LogEntry("CPDuplicateKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}
	
	CSP_UnlockMutex();
	LogEntry("CPDuplicateKey", "end", 0, 10);
	return TRUE;
}


//25 CPHashSessionKey	ACTION
CSPINTERFACE BOOL WINAPI CPHashSessionKey(
	__in HCRYPTPROV hProv,
	__in HCRYPTHASH hHash,
	__in HCRYPTKEY hKey,
	__in DWORD dwFlags
	)
{
#ifdef DEBUG
	puts("CPHashSessionKey");
#endif
	LogEntry("CPHashSessionKey", "start", 0, 10);
	CSP_LockMutex();
	
	if (!(getMutexFlag() & hProv)) {
		//LogEntry(" HCRYPTPROV hProv", "error", -1, 0);
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		CSP_UnlockMutex();
		return FALSE;
	}

	//函数模型 需修改参数
	genhashImpl();
	
	CSP_UnlockMutex();
	LogEntry("CPHashSessionKey", "end", 0, 10);
	return TRUE;
}




