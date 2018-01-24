#include "stdafx.h"
#include "source_backup.h"

/*
 *早期源码备份 方便查询 测试.
 */


#if 0
//Context 初始化
int CPAcquireContextImpl() {
	int rv;

	//加载配置文件
	if ((rv = initCspServiceImpl())<0) {
		LogEntry("CPAcquireContext", "initCspServiceImpl error", rv, 0);
		return rv;
	}
	//加密机状态
	if ((rv = testSjl22ServiceImpl()) != 0) {
		LogEntry("CPAcquireContext", "testSjl22ServiceImpl error", rv, 0);
		return rv;
	}
	return 0;
}

int CPGetProvParamImpl(HCRYPTPROV hProv, DWORD dwParam, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	HKEY hKey;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//获取注册表属性
	ret = GMN_RegOpen(&hKey);
	if (ERROR_SUCCESS != ret) {
		VarLogEntry(" GMN_RegOpen", "error:", ret, 0);
		return ret;
	}

	//获取属性
	ret = GMN_RegQueryValueEx(hKey, (CHAR*)dwParam, 0, &dwFlags, pbData, pdwDataLen);
	if (ERROR_SUCCESS != ret) {
		VarLogEntry(" GMN_RegQueryValueEx", "error: ret", ret, 0);
		VarLogEntry(" GMN_RegQueryValueEx", "key: %s", -1, 0,
			(CHAR*)dwParam);
		return ret;
	}
	GMN_RegCloseKey(hKey);
	return ret;
}

int CPSetProvParamImpl(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD dwFlags) {
	int ret = 0;
	HKEY hKey;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//获取注册表属性
	ret = GMN_RegOpen(&hKey);
	if (ERROR_SUCCESS != ret) {
		VarLogEntry(" GMN_RegOpen", "error", ret, 0);
		return ret;
	}
	//设置注册表属性
	ret = GMN_RegSetValueEx(hKey, (LPCSTR)dwParam, 0,
		(NULL == dwFlags ? REG_SZ : dwFlags),
		pbData, strlen((char*)pbData));
	if (ERROR_SUCCESS != ret) {
		VarLogEntry(" GMN_RegSetValueEx", "error", ret, 0);
		return ret;
	}
	GMN_RegCloseKey(hKey);
	return ret;
}

int CPDeriveKeyImpl(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, HCRYPTKEY *phKey) {
	int ret = 0;
	///////////////////////////
	int timeout = 0;
	int comid;
	CHAR cKey[256];
	UCHAR deriveKey[256];
	UCHAR checkValue[256];
	HKEY_Z *hKey_z = (HKEY_Z*)phKey;
	char *key = (CHAR*)hKey_z->key;
	int algo = Algid;
	char *data = (char*)hBaseData;
	int dataLen = strlen(data);
	int keyLen = strlen(key) / 2;
	int derivationmode = 0;
	int encmode = 0;
	char deriveKeyType[] = ZMK_TYPE;
	char derivationKeyType[] = ZMK_TYPE;
	char *iv = NULL;
	int deriveKeyLen;
	HKEY_Z *hKey_deri;

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
	PackBCD(key, (unsigned char*)cKey, strlen(key));
	__try {
		ret = derivatekey(comid, 0, NULL, algo, derivationmode, encmode, deriveKeyType, derivationKeyType, keyLen, cKey, dataLen, iv, data, 0, NULL, NULL, (char*)deriveKey, (char*)checkValue);
		if (ret<0) {
			VarLogEntry("derivatekey", "error", ret, 0);
			return ret;
		}
		deriveKeyLen = strlen((CHAR*)deriveKey);

		hKey_deri = (HKEY_Z *)malloc(sizeof(HKEY_Z));
		if (NULL == hKey_deri) {
			VarLogEntry("CPDeriveKey", "memory error", -1, 0);
			return -1;
		}

		hKey_deri->len = deriveKeyLen;
		memcpy(hKey_deri->key, deriveKey, deriveKeyLen);
		memcpy(hKey_deri->key, checkValue, strlen((CHAR*)checkValue));
		sprintf((CHAR*)hKey_deri->ALGID, "%02d", algo);
		sprintf((CHAR*)hKey_deri->KEYLEN, "%04d", deriveKeyLen);
		*phKey = (LONG)hKey_deri;
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	//////////////////////////
	return ret;
}

int CPExportKeyImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	ret = exportrsadeskeyService(hKey, hPubKey, pbData, (int *)pdwDataLen);
	if (ret<0 || pdwDataLen<0) {
		VarLogEntry("CPExportKey", "exportrsadeskeyService error", ret, 0);
		return ret;
	}
	return ret;
}

int CPGenKeyImpl(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey) {
	int ret = 0;
	int timeout = 0;
	int comid;
	PHKEY_Z hKey = NULL;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	__try {
		comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
		if (comid<0) {
			VarLogEntry(" InitHsmDevice", "connect error", comid, 0);
			return comid;
		}

		switch (Algid)
		{
		case ALGO_DESTDES:
			ret = generateKeyServiceImpl(comid, hKey);
			if (ret<0) {
				return ret;
			}
			break;
		case SIG_ALGO_RSA:
			ret = genrsakeyServiceImpl(hProv, dwFlags, hKey, comid);
			if (ret < 0) {
				return ret;
			}
			break;
		default:
			VarLogEntry(" CPGenKey", "Algid error", Algid, 0);
			return -1;
		}
		*phKey = (LONG)hKey;
	}
	__finally {
		CloseHsmDevice(comid);
	}
	return ret;
}

int CPGenRandomImpl(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {
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
		ret = genrandom(comid, 0, NULL, dwLen, pbBuffer);
		if (ret<0) {
			VarLogEntry(" genrandom", "error", ret, 0);
			return ret;
		}
	}
	__finally {
		CloseHsmDevice(comid);
	}
	///////////////////////////
	return ret;
}

int CPGetKeyParamImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen) {
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	/////
	if (hKey == NULL) {
		VarLogEntry(" CPGetKeyParam", "hKey == NULL error", -1, 0);
		return -1;
	}

	HKEY_Z * tmpKey = (HKEY_Z *)hKey;
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
		*pcbDataLen = strlen((CHAR*)tmpKey->ALGID);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->ALGID, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_BLOCKLEN:
		*pcbDataLen = strlen((CHAR*)tmpKey->BLOCKLEN);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->BLOCKLEN, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_KEYLEN:
		*pcbDataLen = strlen((CHAR*)tmpKey->KEYLEN);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->KEYLEN, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_SALT:
		*pcbDataLen = strlen((CHAR*)tmpKey->SALT);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->SALT, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_PERMISSIONS:
		*pcbDataLen = strlen((CHAR*)tmpKey->PERMISSIONS);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->PERMISSIONS, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_IV:
		*pcbDataLen = strlen((CHAR*)tmpKey->IV);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->IV, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_PADDING:
		*pcbDataLen = strlen((CHAR*)tmpKey->PADDING);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->PADDING, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_MODE:
		*pcbDataLen = strlen((CHAR*)tmpKey->MODE);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->MODE, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_MODE_BITS:
		*pcbDataLen = strlen((CHAR*)tmpKey->MODE_BITS);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->MODE_BITS, *pcbDataLen);
		}
		ret = 0;
		break;
	case KP_EFFECTIVE_KEYLEN:
		*pcbDataLen = strlen((CHAR*)tmpKey->EFFECTIVE_KEYLEN);
		if (pcbDataLen == 0) {
			VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
			ret = -1;
			break;
		}
		if (NULL != pbData) {
			memcpy(pbData, tmpKey->EFFECTIVE_KEYLEN, *pcbDataLen);
		}
		ret = 0;
		break;
	default:
		ret = -1;
		VarLogEntry(" CPGetKeyParam", "dwParam error", dwParam, 0);
		break;
	}
	return ret;
}

int CPGetUserKeyImpl(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey) {
	int ret = 0;
	HKEY_Z * hzKey;

	DWORD dwKeyLen = sizeof(HKEY_Z);
	hzKey = (PHKEY_Z)malloc(dwKeyLen);
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	if (NULL == hzKey) {
		LogEntry("CPGetUserKey", "Memory error", -1, 0);
		return -1;
	}
	/*
	从密钥容器中获取已持久化的用户密钥句柄:从容器中获取RSA的密钥文件ID标识和。
	dwKeySpec phUserKey 根据密钥属性获取密钥句柄
	1. AT_KEYEXCHANGE 交换密钥
	2. AT_SIGNATURE 签名密钥
	*/
	switch (dwKeySpec)
	{
	case AT_KEYEXCHANGE:
		ret = CPGetProvParamImpl(hProv, AT_KEYEXCHANGE, REG_BINARY, (BYTE*)hzKey, &dwKeyLen);
		if (ERROR_SUCCESS != ret || dwKeyLen <= 0) {
			free(hzKey);
			return -1;
			LogEntry("CPGetUserKey", "AT_KEYEXCHANGE error", ret, 0);
		}
		break;
	case AT_SIGNATURE:
		ret = CPGetProvParamImpl(hProv, AT_SIGNATURE, REG_BINARY, (BYTE *)hzKey, &dwKeyLen);
		if (ERROR_SUCCESS != ret || dwKeyLen <= 0) {
			free(hzKey);
			return -1;
			LogEntry("CPGetUserKey", "AT_SIGNATURE error", ret, 0);
		}
		break;
	default:
		LogEntry("CPGetUserKey", "dwKeySpec error", dwKeySpec, 0);
		return -1;
		break;
	}
	phUserKey = (HCRYPTKEY *)hzKey;

	return ret;
}

int CPImportKeyImpl(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey) {
	int ret = 0;
	HPKEY_Z * pKey;
	HKEY_Z * hKey;
	UCHAR wkLmk[255];
	int keylen;
	UCHAR cv[64];

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	pKey = (HPKEY_Z*)hPubKey;
	ret = importrsadeskeyServiceImpl((UCHAR *)pbData, dwDataLen, pKey->pvKey, pKey->pvLen, wkLmk, &keylen, cv);
	if (ret != 0) {
		VarLogEntry(" importrsadeskeyServiceImplvoid", "error", ret, 0);
		return ret;
	}
	hKey = (HKEY_Z *)malloc(sizeof(HKEY_Z));
	if (NULL == hKey) {
		VarLogEntry(" CPImportKey", "memory error", -1, 0);
		return -1;
	}
	hKey->len = keylen;
	memcpy(hKey->key, wkLmk, keylen);
	memcpy(hKey->cv, cv, strlen((CHAR*)cv));
	*phKey = (LONG)hKey;
	return ret;
}

int CPSetKeyParamImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD dwFlags) {
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	PHKEY_Z phKey = (PHKEY_Z)hKey;
	if (phKey == NULL) {
		VarLogEntry(" CPSetKeyParamImpl", "Memory error", -1, 0);
		return -1;
	}

	switch (dwParam)
	{
	case KP_ALGID:
		memcpy(phKey->ALGID, pbData, sizeof(pbData));
		break;
	case KP_BLOCKLEN:
		memcpy(phKey->BLOCKLEN, pbData, sizeof(pbData));
		break;
	case KP_KEYLEN:
		memcpy(phKey->KEYLEN, pbData, sizeof(pbData));
		break;
	case KP_SALT:
		memcpy(phKey->SALT, pbData, sizeof(pbData));
		break;
	case KP_PERMISSIONS:
		memcpy(phKey->PERMISSIONS, pbData, sizeof(pbData));
		break;
	case KP_IV:
		memcpy(phKey->IV, pbData, sizeof(pbData));
		break;
	case KP_PADDING:
		memcpy(phKey->PADDING, pbData, sizeof(pbData));
		break;
	case KP_MODE:
		memcpy(phKey->MODE, pbData, sizeof(pbData));
		break;
	case KP_MODE_BITS:
		memcpy(phKey->MODE_BITS, pbData, sizeof(pbData));
		break;
	case KP_EFFECTIVE_KEYLEN:
		memcpy(phKey->EFFECTIVE_KEYLEN, pbData, sizeof(pbData));
		break;
	default:
		VarLogEntry(" CPSetKeyParamImpl", "dwParam error", dwParam, 0);
		return -1;
	}
	return ret;
}

int CPDecryptImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	int timeout = 0;
	int comid;
	char *key;
	int dataLen;
	char *data;
	PHKEY_Z phKey = NULL;
	char *ip;
	int port;


	ip = getHsmIP();
	port = getHsmPORT();
	key = (CHAR*)phKey->key;
	dataLen = *pdwDataLen;
	data = (CHAR*)pbData;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	phKey = (PHKEY_Z)hKey;
	if (NULL == phKey) {
		VarLogEntry(" CPDecryptImpl", "hKey error", -1, 0);
		return -1;
	}
	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" CPDecryptImpl", "InitHsmDevice error", comid, 0);
		return comid;
	}
	/////////////////////////////////////
	__try {
		int algo = 0;
		int dataBlockFlag = 0;
		int encryptFlag = 0;
		int algoOperationMode = 0;
		int inputFormat = 1;
		int outputFormat = 1;
		char keyType[] = ZEK_TYPE;
		int paddingMode = 0;
		char paddingChar[] = "0000";
		int paddingFlag = 0;
		char *iv = NULL;
		int outFlag;

		encryptFlag = 1;
		ret = encryptDecrypt(comid, 0, NULL, algo,
			dataBlockFlag,
			encryptFlag,
			algoOperationMode,
			inputFormat,
			outputFormat,
			keyType,
			key,
			paddingMode,
			paddingChar,
			paddingFlag,
			iv,
			&outFlag,
			&dataLen,
			data);
		if (ret < 0) {
			VarLogEntry(" CPDecryptImpl", "encryptDecrypt error", ret, 0);
			return ret;
		}
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return 0;


	return ret;
}

int CPEncryptImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
	int ret = 0;
	int timeout = 0;
	int comid;
	char *key;
	PHKEY_Z phKey = NULL;
	char *ip;
	int port;
	phKey = (PHKEY_Z)hKey;


	ip = getHsmIP();
	port = getHsmPORT();
	key = (CHAR*)phKey->key;
	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	if (NULL == phKey) {
		VarLogEntry(" CPEncryptImpl", "hKey error", -1, 0);
		return -1;
	}

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" CPEncryptImpl", "InitHsmDevice error", comid, 0);
		return comid;
	}
	/////////////////////////////////////
	__try {
		int algo = 0;
		int dataBlockFlag = 0;
		int encryptFlag = 0;
		int algoOperationMode = 0;
		int inputFormat = 1;
		int outputFormat = 1;
		char keyType[] = ZEK_TYPE;
		int paddingMode = 0;
		char paddingChar[] = "0000";
		int paddingFlag = 0;
		char *iv = NULL;
		int outFlag;

		ret = encryptDecrypt(comid, 0, NULL, algo,
			dataBlockFlag,
			encryptFlag,
			algoOperationMode,
			inputFormat,
			outputFormat,
			keyType,
			key,
			paddingMode,
			paddingChar,
			paddingFlag,
			iv,
			&outFlag,
			(int*)pdwDataLen,
			(CHAR*)pbData);
		if (ret < 0) {
			VarLogEntry(" CPEncryptImpl", "encryptDecrypt error", ret, 0);
			return ret;
		}
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return ret;
}

int CPCreateHashImpl(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) {
	int ret = 0;
	int algo;
	PHHASH_Z phHash_z;
	/*
	HASH_MD2        0
	HASH_SHA1       1
	HASH_MD5        2
	HASH_ISO10118_2 3
	HASH_NOHASH     4
	HASH_SHA224     5
	HASH_SHA256     6
	HASH_SHA384     7
	HASH_SHA512     8
	HASH_MD4        9
	HASH_RIPEMD128  10
	HASH_RIPEMD160  11
	HASH_RIPEMD256  12
	HASH_RIPEMD320  13
	HASH_SM3  14
	*/

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	switch (Algid)
	{
	case HASH_MD2:
		algo = HASH_MD2;
		break;
	case HASH_SHA1:
		algo = HASH_SHA1;
		break;
	case HASH_MD5:
		algo = HASH_MD5;
		break;
	case HASH_ISO10118_2:
		algo = HASH_ISO10118_2;
		break;
	case HASH_NOHASH:
		algo = HASH_NOHASH;
		break;
	case HASH_SHA224:
		algo = HASH_SHA224;
		break;
	case HASH_SHA256:
		algo = HASH_SHA256;
		break;
	case HASH_SHA384:
		algo = HASH_SHA384;
		break;
	case HASH_SHA512:
		algo = HASH_SHA512;
		break;
	case HASH_MD4:
		algo = HASH_MD4;
		break;
	case HASH_RIPEMD128:
		algo = HASH_RIPEMD128;
		break;
	case HASH_RIPEMD160:
		algo = HASH_RIPEMD160;
		break;
	case HASH_RIPEMD256:
		algo = HASH_RIPEMD256;
		break;
	case HASH_RIPEMD320:
		algo = HASH_RIPEMD320;
		break;
	case HASH_SM3:
		algo = HASH_SM3;
		break;
	default:
		VarLogEntry(" CPCreateHashImpl", "Algid error", Algid, 0);
		return  -1;
	}
	phHash_z = (PHHASH_Z)malloc(sizeof(HHASH_Z));
	if (NULL != phHash_z) {
		VarLogEntry(" CPCreateHashImpl", "Memory error", -1, 0);
		return -1;
	}
	phHash_z->phKey = (PHKEY_Z)hKey;
	memcpy(phHash_z->ALGID, "%02d", algo);
	*phHash = (HCRYPTHASH)phHash_z;
	return ret;
}

int CPGetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags) {
	int ret = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	/*
	HP_ALGID
	HP_HASHVAL
	HP_HASHSIZE
	HP_HMAC_INFO
	HP_TLS1PRF_LABEL
	HP_TLS1PRF_SEED
	*/
	PHHASH_Z phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" CPGetHashParamImpl", "hHash error", -1, 0);
		return (-1);
	}
	switch (dwParam)
	{
	case HP_ALGID:
		*pdwDataLen = strlen((CHAR*)phzHash->ALGID);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPGetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		if (NULL != pbData) {
			memcpy(pbData, phzHash->ALGID, *pdwDataLen);
		}
		break;
	case HP_HASHVAL:
		*pdwDataLen = strlen((CHAR*)phzHash->HASHVAL);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPGetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		if (NULL != pbData) {
			memcpy(pbData, phzHash->HASHVAL, *pdwDataLen);
		}
		break;
	case HP_HASHSIZE:
		*pdwDataLen = strlen((CHAR*)phzHash->HASHSIZE);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPGetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		if (NULL != pbData) {
			memcpy(pbData, phzHash->HASHSIZE, *pdwDataLen);
		}
		break;
	case HP_HMAC_INFO:
		*pdwDataLen = strlen((CHAR*)phzHash->HMAC_INFO);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPGetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		if (NULL != pbData) {
			memcpy(pbData, phzHash->HMAC_INFO, *pdwDataLen);
		}
		break;
	case HP_TLS1PRF_LABEL:
		*pdwDataLen = strlen((CHAR*)phzHash->TLS1PRF_LABEL);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPGetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		if (NULL != pbData) {
			memcpy(pbData, phzHash->TLS1PRF_LABEL, *pdwDataLen);
		}
		break;
	case HP_TLS1PRF_SEED:
		*pdwDataLen = strlen((CHAR*)phzHash->TLS1PRF_SEED);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPGetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		if (NULL != pbData) {
			memcpy(pbData, phzHash->TLS1PRF_SEED, *pdwDataLen);
		}
		break;
	default:
		VarLogEntry(" CPGetHashParamImpl", "dwParam error", dwParam, 0);
		return (-1);
	}

	return ret;
}

int CPHashDataImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) {
	int ret = 0;
	int timeout = 0;
	int comid;
	char * ip = getHsmIP();
	int port = getHsmPORT();
	PHHASH_Z phzHash = (PHHASH_Z)hHash;
	int hash_id = atoi((CHAR*)phzHash->ALGID);
	UCHAR *data = (UCHAR*)pbData;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//
	if (NULL == phzHash) {
		VarLogEntry(" CPHashDataImpl", "hHash error", -1, 0);
		return -1;
	}
	//
	comid = InitHsmDevice(ip, port, timeout);
	if (comid<0) {
		VarLogEntry(" CPHashDataImpl", "InitHsmDevice error", comid, 0);
		return (-1);
	}
	//
	ret = genhash(comid, 0, NULL, hash_id, dwDataLen, (UCHAR*)pbData, (UCHAR*)pbData);
	if (ret != 0) {
		CloseHsmDevice(comid);
		VarLogEntry(" CPHashDataImpl", "genhash error", ret, 0);
		return (ret);
	}
	//
	CloseHsmDevice(comid);
	return ret;
}

int CPSetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags) {
	int ret = 0;
	DWORD *pdwDataLen = 0;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	/*
	HP_ALGID
	HP_HASHVAL
	HP_HASHSIZE
	HP_HMAC_INFO
	HP_TLS1PRF_LABEL
	HP_TLS1PRF_SEED
	*/
	PHHASH_Z phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" CPSetHashParamImpl", "hHash error", -1, 0);
		return (-1);
	}
	switch (dwParam)
	{
	case HP_ALGID:
		*pdwDataLen = strlen((CHAR*)pbData);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPSetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		memcpy(phzHash->ALGID, pbData, *pdwDataLen);
		break;
	case HP_HASHVAL:
		*pdwDataLen = strlen((CHAR*)pbData);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPSetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		memcpy(phzHash->HASHVAL, pbData, *pdwDataLen);
		break;
	case HP_HASHSIZE:
		*pdwDataLen = strlen((CHAR*)pbData);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPSetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		memcpy(phzHash->HASHSIZE, pbData, *pdwDataLen);
		break;
	case HP_HMAC_INFO:
		*pdwDataLen = strlen((CHAR*)pbData);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPSetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		memcpy(phzHash->HMAC_INFO, pbData, *pdwDataLen);
		break;
	case HP_TLS1PRF_LABEL:
		*pdwDataLen = strlen((CHAR*)pbData);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPSetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		memcpy(phzHash->TLS1PRF_LABEL, pbData, *pdwDataLen);
		break;
	case HP_TLS1PRF_SEED:
		*pdwDataLen = strlen((CHAR*)pbData);
		if (0 == *pdwDataLen) {
			VarLogEntry(" CPSetHashParamImpl", "dwParam Empty", -1, 0);
			return (-1);
		}
		memcpy(phzHash->TLS1PRF_SEED, pbData, *pdwDataLen);
		break;
	default:
		VarLogEntry(" CPSetHashParamImpl", "dwParam error", dwParam, 0);
		return (-1);
	}
	return ret;
}

int CPSignHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR sDescription, DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen) {
	int comid;
	int ret = 0;
	PHKEY_Z phzKey;
	int timeout = 0;
	PHHASH_Z phzHash = NULL;

	char *ip = getHsmIP();
	int port = getHsmPORT();
	int hash_id = atoi((CHAR*)phzHash->ALGID);
	int data_length = *pdwSigLen;
	UCHAR * data = pbSignature;

	//容器是否初始化
	ret = initJudgmentService(hProv);
	if (ret != 0) {
		return ret;
	}
	//hash对象
	phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" CPSignHashImpl", "hHash error", -1, 0);
		return -1;
	}
	//密钥对象
	phzKey = phzHash->phKey;
	if (NULL == phzKey) {
		VarLogEntry(" CPSignHashImpl", "hKey error", -1, 0);
		return -1;
	}
	//////////////
	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" CPSignHashImpl", "InitHsmDevice error", comid, 0);
		return (comid);
	}

	__try {
		int msghdlen = 0;
		char *msghd = NULL;
		int sign_id = 01;
		int pad_mode = 01;
		int mgfHash = NULL;
		int OAEP_parm_len = NULL;
		UCHAR *OAEP_parm = NULL;
		int pssRule = NULL;
		int trailerField = NULL;
		int index = 99;
		int authenDataLen = 0;
		UCHAR * authenData = NULL;

		ret = rsaprisign(comid, msghdlen, msghd, hash_id, sign_id,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			pssRule,
			trailerField,
			data_length,
			data,
			index,
			phzKey->pvLen,
			phzKey->pvKey,
			pbSignature,
			(int *)pdwSigLen);
		if (ret < 0) {
			VarLogEntry(" CPSignHashImpl", "rsaprisign error", ret, 0);
			return ret;
		}
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return ret;
}

int CPVerifySignatureImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR sDescription, DWORD dwFlags) {
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
	////////////////////////////////
	//hash对象
	phzHash = (PHHASH_Z)hHash;
	if (NULL == phzHash) {
		VarLogEntry(" CPVerifySignatureImpl", "hHash error", -1, 0);
		return -1;
	}
	//密钥对象
	phzKey = phzHash->phKey;
	if (NULL == phzKey) {
		VarLogEntry(" CPVerifySignatureImpl", "hKey error", -1, 0);
		return -1;
	}
	//////////////
	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		VarLogEntry(" CPVerifySignatureImpl", "InitHsmDevice error", comid, 0);
		return (comid);
	}
	__try {
		int msghdlen = 0;
		char *msghd = NULL;
		int hash_id = 01;
		int sign_id = 01;
		int pad_mode = 01;
		int mgfHash = NULL;
		int OAEP_parm_len = NULL;
		UCHAR *OAEP_parm = NULL;
		int pssRule = NULL;
		int trailerField = NULL;
		int index = 99;
		int authenDataLen = 0;
		UCHAR * authenData = NULL;
		///////////////////////////////////
		ret = rsapubverify(comid, msghdlen, msghd, hash_id, sign_id,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			pssRule,
			trailerField,
			dwSigLen,
			(UCHAR*)pbSignature,
			strlen((CHAR*)dwFlags),
			(UCHAR*)dwFlags,
			index,
			NULL,
			phzKey->puKey,
			phzKey->puLen,
			authenDataLen,
			authenData
		);
		if (0 != ret) {
			VarLogEntry(" CPVerifySignatureImpl", "rsapubverify error", ret, 0);
			return ret;
		}
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	////////////////////////////////
	return ret;
}

int CPHashSessionKeyImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags) {
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
		VarLogEntry(" CPHashSessionKeyImpl", "hHash NULL", -1, 0);
		return -1;
	}
	//
	if (NULL == phzKey) {
		VarLogEntry(" CPHashSessionKeyImpl", "hKey NULL", -1, 0);
		return -1;
	}
	//
	comid = InitHsmDevice(ip, port, timeout);
	if (comid<0) {
		VarLogEntry(" CPHashSessionKeyImpl", "InitHsmDevice error", comid, 0);
		return (-1);
	}
	//
	ret = genhash(comid, 0, NULL, hash_id, phzKey->len, phzKey->key, phzHash->keyHashValue);
	if (ret != 0) {
		CloseHsmDevice(comid);
		VarLogEntry(" CPHashSessionKeyImpl", "genhash error", ret, 0);
		return (ret);
	}
	//
	CloseHsmDevice(comid);
	return ret;
}
#endif

/*
int genSm2KeyServiceImpl_backup() {
	int ret = 0;

	///////////////////////////
	int comid;
	int msghdlen = 0;
	char *msghd = NULL;
	int algflag = 3;
	int key_usage = 3;
	int compflag = 4;
	int key_length = 256;
	int index = 01;
	int Plen = 0;
	UCHAR *Pbuf = NULL;
	int Alen = 0;
	UCHAR *Abuf = NULL;
	int Blen = 0;
	UCHAR *Bbuf = NULL;
	int Gxlen = 0;
	UCHAR *Gxbuf = NULL;
	int Gylen = 0;
	UCHAR *Gybuf = NULL;
	int Nlen = 0;
	UCHAR *Nbuf = NULL;
	UCHAR puKey[4096], pvKey[4096], deKey[4096];
	int puLen, pvLen, deLen;
	UCHAR *public_key = puKey;
	int * public_key_len = &puLen;
	UCHAR *private_key = pvKey;;
	int *private_key_len = &pvLen;
	UCHAR *derpubkey = deKey;
	int * derpubkeylen = &deLen;
	///////////////////////////////////////////

	char ip[] = "192.168.1.205";
	int port = 8000;
	int timeout = 0;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		puts("connect error");
	}
	puts("------------>connect success");
	__try {
		ret = gensm2key(comid, msghdlen, msghd, algflag, key_usage, compflag, key_length, index, Plen, Pbuf, Alen, Abuf, Blen,
			Bbuf, Gxlen, Gxbuf, Gylen, Gybuf, Nlen, Nbuf, public_key, public_key_len, private_key, private_key_len, derpubkey, derpubkeylen);
		printf("RET:%d\n", ret);
		printf("PUBLIC KEY LEN %d\n", puLen);
		printf("PUBLIC KEY LEN %d\n", pvLen);
		printf("PUBLIC KEY LEN %d\n", deLen);
	}
	__finally {
		CloseHsmDevice(comid);
	}
	return ret;
}

int encryptDecryptImpl() {
	char ip[] = "192.168.1.205";
	int port = 8000;
	int timeout = 0;
	int comid;
	int ret = 0;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		puts("connect error");
	}
	puts("------------>connect success");
	/////////////////////////////////////
	/////////////////////////////////////
	__try {
		int algo = 0;
		int dataBlockFlag = 0;
		int encryptFlag = 0;
		int algoOperationMode = 0;
		int inputFormat = 1;
		int outputFormat = 1;
		char keyType[] = ZEK_TYPE;
		char key[] = "XCB8B629920622806464AB4C738053BFA";
		int paddingMode = 0;
		char paddingChar[] = "0000";
		int paddingFlag = 0;
		char *iv = NULL;
		int outFlag;
		int dataLen = 8;
		char data[] = "AAAAAAAAAAAAAAAA";

		ret = encryptDecrypt(comid, 0, NULL, algo,
			dataBlockFlag,
			encryptFlag,
			algoOperationMode,
			inputFormat,
			outputFormat,
			keyType,
			key,
			paddingMode,
			paddingChar,
			paddingFlag,
			iv,
			&outFlag,
			&dataLen,
			data);
		if (ret < 0) {
			printf("RET:%d\n", ret);
			return ret;
		}
		printf("LEN:%d\n", dataLen);
		printf("DATA:%s\n", data);

		encryptFlag = 1;
		ret = encryptDecrypt(comid, 0, NULL, algo,
			dataBlockFlag,
			encryptFlag,
			algoOperationMode,
			inputFormat,
			outputFormat,
			keyType,
			key,
			paddingMode,
			paddingChar,
			paddingFlag,
			iv,
			&outFlag,
			&dataLen,
			data);
		if (ret < 0) {
			printf("RET:%d\n", ret);
			return ret;
		}
		printf("LEN:%d\n", dataLen);
		printf("DATA:%s\n", data);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return 0;
}

int genhashImpl() {
	char ip[] = "192.168.1.209";
	int port = 8000;
	int timeout = 0;
	int ret = -1;
	int comid;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid<0) {
		puts("connect error");
	}
	puts("connect success");

	ret = testHSM(comid, 0, NULL, NULL, NULL);
	if (ret != 0) {
		printf("RETURN: %d\n", ret);
	}

	const int rndLen = 64;
	UCHAR rnd[rndLen + 1];

	ret = genrandom(comid, 0, NULL, rndLen, rnd);
	if (ret != 0) {
		printf("RETURN: %d LINE: %d\n", ret, __LINE__);
	}
	puts("------------------------RANDOM------------------------------");
	for (int i = 0; i<rndLen; i++) {
		printf("%02X ", rnd[i]);
	}
	printf("\n");

	int hash_id = HASH_SHA1;
	UCHAR data[] = "zhuheng";
	int data_len = strlen((char*)data);
	UCHAR hash_value[256];
	memset(hash_value, 0x00, sizeof(hash_value));

	ret = genhash(comid, 0, NULL, hash_id, data_len, data, hash_value);
	if (ret != 0) {
		printf("RETURN: %d LINE: %d\n", ret, __LINE__);
	}

	printf("DATA LEN: %d\n", data_len);
	puts("------------------------HASH------------------------------");
	for (int i = 0; i < (int)strlen((char*)hash_value); i++) {
		printf("%02X ", hash_value[i]);
	}
	printf("\n");

	CloseHsmDevice(comid);
	return ret;
}

int rsaprisignImpl() {

	UCHAR public_key[4096];
	int  public_key_len = sizeof(public_key);
	UCHAR private_key[4096];
	int  private_key_len = sizeof(private_key);
	//testEight(public_key, &public_key_len, private_key, &private_key_len);
	//printf("PUBLEN: %d PRILEN:%d\n", public_key_len, private_key_len);

	puts("------------------------------------------------------------------------");

	////////////////////////////////
	char ip[] = "192.168.1.205";
	int port = 8000;
	int timeout = 0;
	int comid;
	int ret = 0;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		puts("connect error");
	}
	puts("------------>connect success");
	__try {
		int msghdlen = 0;
		char *msghd = NULL;
		int hash_id = 01;
		int sign_id = 01;
		int pad_mode = 01;
		int mgfHash = NULL;
		int OAEP_parm_len = NULL;
		UCHAR *OAEP_parm = NULL;
		int pssRule = NULL;
		int trailerField = NULL;
		int data_length = 8;
		UCHAR data[] = "zhuheng0";
		int index = 99;
		UCHAR sign[4096];
		int sign_length;
		int authenDataLen = 0;
		UCHAR * authenData = NULL;

		ret = rsaprisign(comid, msghdlen, msghd, hash_id, sign_id,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			pssRule,
			trailerField,
			data_length,
			data,
			index,
			private_key_len,
			private_key,
			sign,
			&sign_length);
		if (ret < 0) {
			printf("RET:%d\n", ret);
			return ret;
		}
		printf("LEN:%d\n", sign_length);

		///////////////////////////////////

		ret = rsapubverify(comid, msghdlen, msghd, hash_id, sign_id,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			pssRule,
			trailerField,
			sign_length,
			sign,
			data_length,
			data,
			index,
			NULL,
			public_key,
			public_key_len,
			authenDataLen,
			authenData
		);
		printf("RET:%d\n", ret);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	////////////////////////////////
	return 0;
}

int rsapubverifyImpl() {

	UCHAR public_key[4096];
	int  public_key_len = sizeof(public_key);
	UCHAR private_key[4096];
	int  private_key_len = sizeof(private_key);
	//testEight(public_key, &public_key_len, private_key, &private_key_len);
	//printf("PUBLEN: %d PRILEN:%d\n", public_key_len, private_key_len);

	puts("------------------------------------------------------------------------");

	////////////////////////////////
	char ip[] = "192.168.1.205";
	int port = 8000;
	int timeout = 0;
	int comid;
	int ret = 0;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		puts("connect error");
	}
	puts("------------>connect success");
	__try {
		int msghdlen = 0;
		char *msghd = NULL;
		int hash_id = 01;
		int sign_id = 01;
		int pad_mode = 01;
		int mgfHash = NULL;
		int OAEP_parm_len = NULL;
		UCHAR *OAEP_parm = NULL;
		int pssRule = NULL;
		int trailerField = NULL;
		int data_length = 8;
		UCHAR data[] = "zhuheng0";
		int index = 99;
		UCHAR sign[4096];
		int sign_length;
		int authenDataLen = 0;
		UCHAR * authenData = NULL;

		ret = rsaprisign(comid, msghdlen, msghd, hash_id, sign_id,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			pssRule,
			trailerField,
			data_length,
			data,
			index,
			private_key_len,
			private_key,
			sign,
			&sign_length);
		if (ret<0) {
			printf("RET:%d\n", ret);
			return ret;
		}
		printf("LEN:%d\n", sign_length);

		///////////////////////////////////

		ret = rsapubverify(comid, msghdlen, msghd, hash_id, sign_id,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			pssRule,
			trailerField,
			sign_length,
			sign,
			data_length,
			data,
			index,
			NULL,
			public_key,
			public_key_len,
			authenDataLen,
			authenData
		);
		printf("RET:%d\n", ret);
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return ret;
	////////////////////////////////
}

void encryptOrDecryptRsaSm2() {
	/////////////////////////////////////////
	UCHAR public_key[4096];
	int  public_key_len;
	UCHAR private_key[4096];
	int  private_key_len = 0;
	//生成密钥对
	//testEight(public_key, &public_key_len, private_key, &private_key_len);
	//printf("PUBLEN: %d PRILEN:%d\n", public_key_len, private_key_len);
	//puts("------------------------------------------------------------------------");
	///////////////////////////////////////////
	//TEMPLATE
	int ret = 0;
	int comid;
	char ip[] = "192.168.1.205";
	int port = 8000;
	int timeout = 0;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		puts("connect error");
	}
	puts("------------>connect success");
	__try {
		/////////////////////////////
		int msghdlen = 0;
		char * msghd = NULL;
		int mgfHash = NULL;
		int OAEP_parm_len = NULL;
		UCHAR *OAEP_parm = NULL;
		int index = 99;

		//RSA 1 SM2 3
		int sig_alg = 1;
		//0加密   1解密
		int dec_flag = 0;
		//RSA 1234 SM2 00
		int pad_mode = 1;

		int sign_length = 8;
		UCHAR *sign = (UCHAR*)"zhuheng0";

		int data_len;
		UCHAR data[4096];
		////////////////////////////
		UCHAR *mac = NULL;
		int authenDataLen = 0;
		UCHAR *authenData = NULL;

		ret = rsapubkeyoper(
			comid,
			msghdlen, msghd,
			sig_alg,
			dec_flag,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			sign_length,
			sign,
			index,
			mac,
			public_key,
			public_key_len,
			authenDataLen,
			authenData,
			data,
			&data_len
		);
		printf("ER RET:%d\n", ret);
		//////////////////解密///////////////////////
		//0加密<-仅限RSA   1解密

		dec_flag = 1;
		UCHAR sign_t[4096];
		int sign_length_t;
		ret = rsaprikeyoper(
			comid,
			msghdlen, msghd,
			sig_alg,
			dec_flag,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			data_len,
			data,
			index,
			private_key_len,
			private_key,
			sign_t,
			&sign_length_t
		);
		printf("EP RET:%d\n", ret);
		////////////////////////////////////////

	}
	__finally {
		CloseHsmDevice(comid);
	}
	//////////////////////////////////////////////
}
*/