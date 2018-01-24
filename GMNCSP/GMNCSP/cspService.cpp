#include "stdafx.h"

/*
*后期可补全  数据校验  补全各种校验  代码健硕行
*/

//1 cpAcquireContext
int cpAcquireContextImpl(HCRYPTPROV *phProv, CHAR *pszContainer, DWORD dwFlags, PVTableProvStruc pVTable){
	if (NULL == phProv) {
		return (-1);
	}
	return  initializeCSPService(phProv);
}

//2 cpGetProvParam
int cpGetProvParamImpl(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	return getParamService(hProv, dwParam, pbData, pdwDataLen, dwFlags);;
}

//3 cpReleaseContext
int cpReleaseContextImpl(HCRYPTPROV hProv, DWORD dwFlags){
	int ret = 0;
	//结束线程同步
	ret = CSP_Destroy_Mutex();
	hProv = 0;
	return ret;
}

//4 cpSetProvParam
int cpSetProvParamImpl(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD dwFlags){
	int ret = 0;
	
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	return  setParamService( hProv,  dwParam, pbData,  dwFlags);
}

//5 cpDeriveKey
int cpDeriveKeyImpl(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey){
	int ret = 0;
	int comid;
	PHKEY_Z phzKey;
	///////////////////////////

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	phzKey = (PHKEY_Z)phKey;
	if (NULL == phzKey) {
		VarLogEntry(" cpDeriveKeyImpl", "NULL == phzKey", -1, 0);
		return -1;
	}
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), 0);
	if (comid<0) {
		VarLogEntry(" InitHsmDevice", "connect error", comid, 0);
		return comid;
	}
	__try {
		ret =  derivatekeyService( comid, phzKey,  Algid,  hBaseData);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	//////////////////////////
	return ret;
}

//6 cpDestroyKey
int cpDestroyKeyImpl(HCRYPTPROV hProv, HCRYPTKEY hKey){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	if (NULL != hKey) {
		free((void*)hKey);
		hKey = NULL;
	}
	return ret;
}

//7 cpExportKey
int cpExportKeyImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, DWORD dwBlobType, 
	DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	ret = exportrsadeskeyService(hKey, hPubKey, pbData, (int *)pdwDataLen);
	if (ret<0 || pdwDataLen<0) {
		VarLogEntry("cpExportKey", "exportrsadeskeyService error", ret, 0);
		return ret;
	}
	return ret;
}

//8 cpGenKey
int cpGenKeyImpl(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey){
	int ret = 0;
	int timeout = 0;
	int comid;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
	if (comid<0) {
		VarLogEntry(" InitHsmDevice", "connect error", comid, 0);
		return comid;
	}

	__try {
		ret = genKeyService( comid,  hProv, Algid,  dwFlags, phKey);
	}
	__finally {
		CloseHsmDevice(comid);
	}
	return ret;
}

//9 cpGenRandom
int cpGenRandomImpl(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer){
	int comid;
	int ret = 0;
	int timeout = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	////////////////////////////
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
	if (comid<0) {
		VarLogEntry(" InitHsmDevice", "connect error", comid, 0);
		return comid;
	}

	__try {
		ret = genRandomService( comid,  dwLen, pbBuffer);
	}
	__finally {
		CloseHsmDevice(comid);
	}
	///////////////////////////
	return ret;
}

//10 cpGetKeyParam
int cpGetKeyParamImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	/////
	HKEY_Z * tmpKey = (HKEY_Z *)hKey;
	if (tmpKey == NULL) {
		VarLogEntry(" cpGetKeyParam", "hKey == NULL error", -1, 0);
		return -1;
	}

	return  getKeyParamService( dwParam, tmpKey,  pbData,  pcbDataLen);
}

//11 cpGetUserKey
int cpGetUserKeyImpl(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey){
	int ret = 0;
	
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}

	return getUserKeyService( hProv,  dwKeySpec, phUserKey);;
}

//12 cpImportKey
int cpImportKeyImpl(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}

	return importKeyService(pbData,  dwDataLen,  hPubKey,  dwFlags, phKey);
}

//13 cpSetKeyParam
int cpSetKeyParamImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD dwFlags){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	PHKEY_Z phKey = (PHKEY_Z)hKey;
	if (phKey == NULL) {
		VarLogEntry(" cpSetKeyParamImpl", "Memory error", -1, 0);
		return -1;
	}

	return setKeyParamService(phKey,  dwParam, pbData);
}

//14 cpDecrypt
int cpDecryptImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen){
	int ret = 0;
	int timeout = 0;
	int comid;
	PHKEY_Z phKey = NULL;
	char *ip;
	int port;


	ip = getHsmIP();
	port = getHsmPORT();

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	phKey = (PHKEY_Z)hKey;
	if (NULL == phKey) {
		VarLogEntry(" cpDecryptImpl", "hKey error", -1, 0);
		return -1;
	}
	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" cpDecryptImpl", "InitHsmDevice error", comid, 0);
		return comid;
	}
	/////////////////////////////////////
	__try {
		ret = decryptService( comid,  phKey, pbData, pdwDataLen);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return ret;
}

//15 cpEncrypt
int cpEncryptImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, 
	DWORD *pdwDataLen, DWORD dwBufLen){
	char *ip;
	int port;
	int comid;
	int ret = 0;
	PHKEY_Z phKey;
	int timeout = 0;
	ip = getHsmIP();
	port = getHsmPORT();
	
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}

	phKey = (PHKEY_Z)hKey;
	if (NULL == phKey) {
		VarLogEntry(" cpEncryptImpl", "hKey error", -1, 0);
		return -1;
	}

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" cpEncryptImpl", "InitHsmDevice error", comid, 0);
		return comid;
	}
	/////////////////////////////////////
	__try {
		ret = encryptService(comid, phKey, pbData, pdwDataLen);
		if (ret < 0) {
			VarLogEntry(" cpDecryptImpl", "encryptService error", ret, 0);
		}
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return ret;
}

//16 cpCreateHash
int cpCreateHashImpl(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	return createHashService( Algid,  hKey, phHash);
}

//17 cpDestroyHash
int cpDestroyHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash){
	int ret = 0;
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}

	if (NULL != hHash) {
		free((void *)hHash);
	}
	return ret;
}

//18 cpDuplicateHash 附加函数
int cpDuplicateHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD *pdwReserved, DWORD dwFlags, HCRYPTHASH *phHash){
	int ret = 0;
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}

	return duplicateHashService( hHash, phHash);
}

//19 cpGetHashParam
int cpGetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags){
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	PHHASH_Z phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" cpGetHashParamImpl", "hHash error", -1, 0);
		return (-1);
	}
	return getHashParamService( dwParam,  phzHash,  pbData, pdwDataLen);
}

//20 cpHashData
int cpHashDataImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags){
	int ret = 0;
	int comid;
	PHHASH_Z phzHash; 
	int timeout = 0;
	char * ip = getHsmIP();
	int port = getHsmPORT();

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//
	phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" cpHashDataImpl", "hHash error", -1, 0);
		return -1;
	}
	//
	comid = InitHsmDevice(ip, port, timeout);
	if (comid<0) {
		VarLogEntry(" cpHashDataImpl", "InitHsmDevice error", comid, 0);
		return (comid);
	}
	__try {
		//
		ret =  hashDataService( comid,  phzHash, pbData,  dwDataLen);
	}
	__finally {
		//
		CloseHsmDevice(comid);
	}
	return ret;
}

//21 cpSetHashParam
int cpSetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags){
	int ret = 0;
	DWORD pdwDataLen = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	PHHASH_Z phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" cpSetHashParamImpl", "hHash error", -1, 0);
		return (-1);
	}
	
	pdwDataLen = strlen((CHAR*)pbData);
	if (0 == pdwDataLen) {
		VarLogEntry(" cpSetHashParamImpl", "pbData Empty error", -1, 0);
		return (-1);
	}

	
	return setHashParamService( phzHash,  dwParam,  pdwDataLen, pbData);
}

//22 cpSignHash
int cpSignHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR sDescription, 
	DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen){
	int comid;
	int ret = 0;
	PHKEY_Z phzKey;
	PHHASH_Z phzHash;
	int timeout = 0;
	char *ip = getHsmIP();
	int port = getHsmPORT();

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//hash对象
	phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" cpSignHashImpl", "hHash error", -1, 0);
		return -1;
	}
	//密钥对象
	phzKey = phzHash->phKey;
	if (NULL == phzKey) {
		VarLogEntry(" cpSignHashImpl", "hKey error", -1, 0);
		return -1;
	}
	//////////////
	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" cpSignHashImpl", "InitHsmDevice error", comid, 0);
		return (comid);
	}

	__try {
		ret = signatureService( comid, phzKey, pbSignature, pdwSigLen,  phzHash);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return ret;
}

//23 cpVerifySignature
int cpVerifySignatureImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbSignature, DWORD dwSigLen, 
	HCRYPTKEY hPubKey, LPCWSTR sDescription, DWORD dwFlags){
	int ret = 0;
	int timeout = 0;
	int comid;
	PHHASH_Z phzHash;
	PHKEY_Z phzKey;
	char * ip = getHsmIP();
	int port = getHsmPORT();

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	
	//hash对象
	phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" cpVerifySignatureImpl", "hHash error", -1, 0);
		return -1;
	}
	//密钥对象
	phzKey = phzHash->phKey;
	if (NULL == phzKey) {
		VarLogEntry(" cpVerifySignatureImpl", "hKey error", -1, 0);
		return -1;
	}
	//////////////
	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" cpVerifySignatureImpl", "InitHsmDevice error", comid, 0);
		return (comid);
	}
	__try {
		ret = verifyService( comid, phzKey, pbSignature, dwSigLen,  phzHash);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	////////////////////////////////
	return ret;
}

//24 cpDuplicateKey 附加函数
int cpDuplicateKeyImpl(HCRYPTPROV hUID, HCRYPTKEY hKey, DWORD *pdwReserved, DWORD dwFlags, HCRYPTKEY *phKey){
	int ret = 0;
	
	//容器是否初始化
	ret = initJudgmentService(hUID);
	if (ret != 0) {
		return ret;
	}
	return duplicateKeyService( hKey, phKey);
	;
}

//25 cpHashSessionKey
int cpHashSessionKeyImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags){
	int ret = 0;
	int timeout = 0;
	int comid;
	char * ip = getHsmIP();
	int port = getHsmPORT();
	PHHASH_Z phzHash = (PHHASH_Z)hHash;
	int hash_id = atoi((CHAR*)phzHash->ALGID);
	PHKEY_Z phzKey = (PHKEY_Z)hKey;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//
	if (NULL == phzHash) {
		VarLogEntry(" cpHashSessionKeyImpl", "hHash NULL", -1, 0);
		return -1;
	}
	//
	if (NULL == phzKey) {
		VarLogEntry(" cpHashSessionKeyImpl", "hKey NULL", -1, 0);
		return -1;
	}
	//
	comid = InitHsmDevice(ip, port, timeout);
	if (comid<0) {
		VarLogEntry(" cpHashSessionKeyImpl", "InitHsmDevice error", comid, 0);
		return (-1);
	}
	__try {
		//
		ret = hashKeyService( comid,  phzHash);
	}
	__finally {
		//
		CloseHsmDevice(comid);
	}
	return ret;
}


