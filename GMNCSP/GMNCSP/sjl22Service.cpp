#include "stdafx.h"

/*
	SERVICE
*/

//初始化
int initializeCSPService(HCRYPTPROV *phProv) {
	int ret = 0;
	//加载配置文件
	if ((ret = initCspServiceImpl()) < 0) {
		LogEntry("cpAcquireContext", "initCspServiceImpl error", ret, 0);
		return ret;
	}
	//加密机状态
	if ((ret = testSjl22ServiceImpl()) != 0) {
		LogEntry("cpAcquireContext", "testSjl22ServiceImpl error", ret, 0);
		return ret;
	}
	*phProv = getMutexFlag();
	return ret;
}

//判断初始化
int initJudgmentService(HCRYPTPROV hProv) {
	//容器是否初始化
	if (!(getMutexFlag() & hProv)) {
		VarLogEntry(" HCRYPTPROV hProv", "error %d %u", -1, 0, getMutexFlag(), hProv);
		return -1;
	}
	return 0;
}

//获取属性
int getParamService(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags) {
	int ret = 0;
	HKEY hKey;

	//获取注册表属性
	ret = GMN_RegOpen(&hKey);
	if (ERROR_SUCCESS != ret) {
		VarLogEntry(" GMN_RegOpen", "error:", ret, 0);
		return ret;
	}
	__try {
		//获取属性
		ret = GMN_RegQueryValueEx(hKey, (CHAR*)dwParam, 0, &dwFlags, pbData, pdwDataLen);
		if (ERROR_SUCCESS != ret) {
			VarLogEntry(" GMN_RegQueryValueEx", "error: ret", ret, 0);
			VarLogEntry(" GMN_RegQueryValueEx", "key: %s", -1, 0,
				(CHAR*)dwParam);
		}
	}
	__finally {
		GMN_RegCloseKey(hKey);
	}

	return ret;
}

//设置属性
int setParamService(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD dwFlags) {
	int ret = 0;

	HKEY hKey;
	//获取注册表属性
	ret = GMN_RegOpen(&hKey);
	if (ERROR_SUCCESS != ret) {
		VarLogEntry(" GMN_RegOpen", "error", ret, 0);
		return ret;
	}
	__try {
		//设置注册表属性
		ret = GMN_RegSetValueEx(hKey, (LPCSTR)dwParam, 0,
			(NULL == dwFlags ? REG_SZ : dwFlags),
			pbData, strlen((char*)pbData));
		if (ERROR_SUCCESS != ret) {
			VarLogEntry(" GMN_RegSetValueEx", "error", ret, 0);
		}
	}
	__finally {
		GMN_RegCloseKey(hKey);
	}
	return ret;
}

//生成密钥
int genKeyService(int comid, HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey) {
	int ret = 0;
	PHKEY_Z hKey = NULL;
	switch (Algid)
	{
	case ALGO_DESTDES:
	case ALGO_SSF33:
	case ALGO_SSF10:
	case ALGO_SCB2:
	case ALGO_SM4:
		ret = generateKeyServiceImpl(comid, hKey, Algid);
		if (ret < 0) {
			return ret;
		}
		break;
	case ALGO_RSA:
		ret = genrsakeyServiceImpl(hProv, dwFlags, hKey, comid, Algid);
		if (ret < 0) {
			return ret;
		}
		break;
	case ALGO_SM2:
		ret = genSm2KeyServiceImpl(hKey, comid, Algid);
		if (ret < 0) {
			return ret;
		}
		break;
	default:
		VarLogEntry(" cpGenKey", "Algid error", Algid, 0);
		return -1;
	}
	*phKey = (LONG)hKey;
	return ret;
}

//生成随机数
int genRandomService(int comid, DWORD dwLen, BYTE *pbBuffer) {
	int ret = 0;
	ret = genrandom(comid, 0, NULL, dwLen, pbBuffer);
	if (ret != 0) {
		VarLogEntry(" genrandom", "error", ret, 0);
	}
	return ret;
}

//获得用户密钥
int getUserKeyService(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey) {
	int ret = 0;
	HKEY_Z * hzKey;
	DWORD dwKeyLen = sizeof(HKEY_Z);
	hzKey = (PHKEY_Z)malloc(dwKeyLen);
	if (NULL == hzKey) {
		LogEntry("cpGetUserKey", "Memory error", -1, 0);
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
		ret = cpGetProvParamImpl(hProv, AT_KEYEXCHANGE, (BYTE*)hzKey, &dwKeyLen, REG_BINARY);
		if (ERROR_SUCCESS != ret || dwKeyLen <= 0) {
			free(hzKey);
			LogEntry("cpGetUserKey", "AT_KEYEXCHANGE error", ret, 0);
			return -1;
		}
		break;
	case AT_SIGNATURE:
		ret = cpGetProvParamImpl(hProv, AT_SIGNATURE, (BYTE *)hzKey, &dwKeyLen, REG_BINARY);
		if (ERROR_SUCCESS != ret || dwKeyLen <= 0) {
			free(hzKey);
			LogEntry("cpGetUserKey", "AT_SIGNATURE error", ret, 0);
			return -1;
		}
		break;
	default:
		free(hzKey);
		LogEntry("cpGetUserKey", "dwKeySpec error", dwKeySpec, 0);
		return -1;
	}
	*phUserKey = (HCRYPTKEY)hzKey;
	return ret;
}

//导出密钥
int importKeyService(const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey) {
	int ret = 0;
	HPKEY_Z * pKey;
	HKEY_Z * hKey;
	UCHAR wkLmk[255];
	int keylen;
	UCHAR cv[64];

	pKey = (HPKEY_Z*)hPubKey;
	if (NULL == pKey) {
		VarLogEntry(" importKeyService", "error", -1, 0);
		return -1;
	}
	ret = importrsadeskeyServiceImpl((UCHAR *)pbData, dwDataLen, pKey->pvKey, pKey->pvLen, wkLmk, &keylen, cv);
	if (ret != 0) {
		VarLogEntry(" importrsadeskeyServiceImpl", "error", ret, 0);
		return ret;
	}
	hKey = (HKEY_Z *)malloc(sizeof(HKEY_Z));
	if (NULL == hKey) {
		VarLogEntry(" cpImportKey", "memory error", -1, 0);
		return -1;
	}
	hKey->len = keylen;
	memcpy(hKey->key, wkLmk, keylen);
	memcpy(hKey->cv, cv, strlen((CHAR*)cv));
	*phKey = (LONG)hKey;
	return ret;
}

//设置密钥属性
int setKeyParamService(PHKEY_Z phKey, DWORD dwParam, BYTE *pbData) {
	int ret = 0;
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
		VarLogEntry(" cpSetKeyParamImpl", "dwParam error", dwParam, 0);
		return -1;
	}
	return ret;
}

//创建hash对象
int createHashService(ALG_ID Algid, HCRYPTKEY hKey, HCRYPTHASH *phHash) {
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
		VarLogEntry(" cpCreateHashImpl", "Algid error", Algid, 0);
		return  -1;
	}
	phHash_z = (PHHASH_Z)malloc(sizeof(HHASH_Z));
	if (NULL != phHash_z) {
		VarLogEntry(" cpCreateHashImpl", "Memory error", -1, 0);
		return -1;
	}
	phHash_z->phKey = (PHKEY_Z)hKey;
	memcpy(phHash_z->ALGID, "%02d", algo);
	*phHash = (HCRYPTHASH)phHash_z;
	return ret;
}

//复制hash对象
int duplicateHashService(HCRYPTHASH hHash, HCRYPTHASH *phHash) {
	int ret = 0;

	if (NULL == (PHHASH_Z)hHash) {
		LogEntry("cpDuplicateHash", "NULL == (PHHASH_Z)hHash", -1, 0);
		return -1;
	}
	PHHASH_Z phzHash;
	phzHash = (PHHASH_Z)malloc(sizeof(HHASH_Z));
	if (NULL == phzHash) {
		LogEntry("cpDuplicateHash", "Memory error", -1, 0);
		return -1;
	}
	memcpy(phzHash, (PHHASH_Z)hHash, sizeof(HHASH_Z));
	*phHash = (HCRYPTHASH)phzHash;
	return ret;
}

//设置hash对象属性
int setHashParamService(PHHASH_Z phzHash, DWORD dwParam, DWORD pdwDataLen, BYTE *pbData) {
	int ret = 0;
	/*
	HP_ALGID
	HP_HASHVAL
	HP_HASHSIZE
	HP_HMAC_INFO
	HP_TLS1PRF_LABEL
	HP_TLS1PRF_SEED
	*/
	switch (dwParam)
	{
	case HP_ALGID:
		memcpy(phzHash->ALGID, pbData, pdwDataLen);
		break;
	case HP_HASHVAL:
		memcpy(phzHash->HASHVAL, pbData, pdwDataLen);
		break;
	case HP_HASHSIZE:
		memcpy(phzHash->HASHSIZE, pbData, pdwDataLen);
		break;
	case HP_HMAC_INFO:
		memcpy(phzHash->HMAC_INFO, pbData, pdwDataLen);
		break;
	case HP_TLS1PRF_LABEL:
		memcpy(phzHash->TLS1PRF_LABEL, pbData, pdwDataLen);
		break;
	case HP_TLS1PRF_SEED:
		memcpy(phzHash->TLS1PRF_SEED, pbData, pdwDataLen);
		break;
	default:
		VarLogEntry(" cpSetHashParamImpl", "dwParam error", dwParam, 0);
		return (-1);
	}

	return ret;
}

//复制密钥对象
int duplicateKeyService(HCRYPTKEY hKey, HCRYPTKEY *phKey) {
	int ret = 0;
	PHKEY_Z phzKey, dupKey;
	int keyLen = sizeof(HKEY_Z);

	//密钥对象
	phzKey = (PHKEY_Z)hKey;
	if (NULL == phzKey) {
		VarLogEntry(" cpDuplicateKey", "hKey error", -1, 0);
		return -1;
	}
	dupKey = (PHKEY_Z)malloc(keyLen);
	if (NULL == dupKey) {
		VarLogEntry(" cpDuplicateKey", "Memory error", -1, 0);
		return -1;
	}
	memcpy(dupKey, phzKey, keyLen);
	*phKey = (HCRYPTKEY)dupKey;
	return ret;
}

//导出密钥
int exportrsadeskeyService(HCRYPTKEY hKey, HCRYPTKEY hPubKey, UCHAR * data, int * data_length) {
	char * ip = getHsmIP();
	int port = getHsmPORT();
	int timeout = 0;
	int comid;
	int ret = 0;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		return comid;
	}
	//////////////////////////
	UCHAR * wkLmk = (UCHAR*)hKey;
	UCHAR * public_key = (UCHAR *)hPubKey;
	int  public_key_len = strlen((CHAR *)hPubKey);
	///////////////////////////
	int msghdlen = 0;
	char * msghd = NULL;
	int algo = 0;
	int sig_alg = 01;
	int pad_mode = 04;
	int mgfHash = NULL;
	int OAEP_parm_len = NULL;
	UCHAR *OAEP_parm = NULL;
	int keyBlockType = 3;
	int keyBlockTemplateLen = NULL;
	UCHAR *keyBlockTemplate = NULL;
	int keyOffset = NULL;
	int chkLen = NULL;
	int chkOffset = NULL;
	int keyLen = 16;
	int keyTypeMode = 0;
	UCHAR keyType[] = ZPK_TYPE;
	int index = -1;
	UCHAR *mac = NULL;
	int authenDataLen = NULL;
	UCHAR *authenData = NULL;
	UCHAR *iv = NULL;
	UCHAR *cv = NULL;

	__try {
		ret = exportrsadeskey(
			comid,
			msghdlen,
			msghd,
			algo,
			sig_alg,
			pad_mode,
			mgfHash,
			OAEP_parm_len,
			OAEP_parm,
			keyBlockType,
			keyBlockTemplateLen,
			keyBlockTemplate,
			keyOffset,
			chkLen,
			chkOffset,
			keyLen,
			keyTypeMode,
			keyType,
			wkLmk,
			index,
			mac,
			public_key,
			public_key_len,
			authenDataLen,
			authenData,
			iv,
			cv,
			data,
			data_length
		);
		if (ret < 0) {
			return ret;
		}
	}
	__finally
	{
		CloseHsmDevice(comid);
	}
	return 0;
}

//设置密钥属性
int getKeyParamService(DWORD dwParam, HKEY_Z * tmpKey, LPBYTE pbData, LPDWORD pcbDataLen) {
	int ret = 0;

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
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->ALGID, pbData, pcbDataLen);
		break;
	case KP_BLOCKLEN:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->BLOCKLEN, pbData, pcbDataLen);
		break;
	case KP_KEYLEN:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->KEYLEN, pbData, pcbDataLen);
		break;
	case KP_SALT:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->SALT, pbData, pcbDataLen);
		break;
	case KP_PERMISSIONS:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->PERMISSIONS, pbData, pcbDataLen);
		break;
	case KP_IV:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->IV, pbData, pcbDataLen);
		break;
	case KP_PADDING:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->PADDING, pbData, pcbDataLen);
		break;
	case KP_MODE:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->MODE, pbData, pcbDataLen);
		break;
	case KP_MODE_BITS:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->MODE_BITS, pbData, pcbDataLen);
		break;
	case KP_EFFECTIVE_KEYLEN:
		ret = getKeyParamServiceImpl((CHAR*)tmpKey->EFFECTIVE_KEYLEN, pbData, pcbDataLen);
		break;
	default:
		VarLogEntry(" CPGetKeyParam", "dwParam error", dwParam, 0);
		return -1;
	}

	if (0 != ret) {
		VarLogEntry(" CPGetKeyParam", "dwParam Empty error", dwParam, 0);
	}
	return ret;
}

//获取hash属性
int getHashParamService(DWORD dwParam, PHHASH_Z phzHash, LPBYTE pbData, LPDWORD pdwDataLen) {
	int ret = 0;
	/*
	HP_ALGID
	HP_HASHVAL
	HP_HASHSIZE
	HP_HMAC_INFO
	HP_TLS1PRF_LABEL
	HP_TLS1PRF_SEED
	*/
	switch (dwParam)
	{
	case HP_ALGID:
		ret = getKeyParamServiceImpl((CHAR*)phzHash->ALGID, pbData, pdwDataLen);
		break;
	case HP_HASHVAL:
		ret = getKeyParamServiceImpl((CHAR*)phzHash->HASHVAL, pbData, pdwDataLen);
		break;
	case HP_HASHSIZE:
		ret = getKeyParamServiceImpl((CHAR*)phzHash->HASHSIZE, pbData, pdwDataLen);
		break;
	case HP_HMAC_INFO:
		ret = getKeyParamServiceImpl((CHAR*)phzHash->HMAC_INFO, pbData, pdwDataLen);
		break;
	case HP_TLS1PRF_LABEL:
		ret = getKeyParamServiceImpl((CHAR*)phzHash->TLS1PRF_LABEL, pbData, pdwDataLen);
		break;
	case HP_TLS1PRF_SEED:
		ret = getKeyParamServiceImpl((CHAR*)phzHash->TLS1PRF_SEED, pbData, pdwDataLen);
		break;
	default:
		VarLogEntry(" CPGetHashParamImpl", "dwParam error", dwParam, 0);
		return (-1);
	}
	if (0 != ret) {
		VarLogEntry(" getHashParamService", "dwParam Empty error", dwParam, 0);
	}
	return ret;
}

//加密
int encryptService(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	int algo;

	algo = atoi((CHAR*)phKey->ALGID);
	switch (algo)
	{
	case ALGO_DESTDES:
	case ALGO_SM4:
	case ALGO_SCB2:
	case ALGO_SSF33:
	case ALGO_SSF10:
		ret = encryptDataServiceImpl(comid, phKey, pbData, pdwDataLen);
		break;
	case ALGO_RSA:
		ret = encryptRSAServiceImpl(comid, phKey, pbData, pdwDataLen);
		break;
	case ALGO_SM2:
		ret = encryptSM2ServiceImpl(comid, phKey, pbData, pdwDataLen);
		break;
	default:
		VarLogEntry(" encryptService", "key algo error", algo, 0);
	}

	return ret;
}

//解密
int decryptService(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	int algo;

	algo = atoi((CHAR*)phKey->ALGID);
	switch (algo)
	{
	case ALGO_DESTDES:
		ret = decryptDataServiceImpl(comid, phKey, pbData, pdwDataLen);
		break;
	case ALGO_RSA:
		ret = decryptRSAServiceImpl(comid, phKey, pbData, pdwDataLen);
		break;
	case ALGO_SM2:
		ret = decryptSM2ServiceImpl(comid, phKey, pbData, pdwDataLen);
		break;
	default:

		return -1;
	}
	return ret;
}

//签名
int signatureService(int comid, PHKEY_Z phKey, BYTE *pbSignature, DWORD *dwSigLen, PHHASH_Z phzHash) {
	int ret = 0;
	int algo;

	algo = atoi((CHAR*)phKey->ALGID);

	//判断算法
	switch (algo)
	{
	case ALGO_RSA:
		ret = signatureRSAServiceImpl(comid, phKey, pbSignature, dwSigLen, phzHash);
	case ALGO_SM2:
		ret = signatureSM2ServiceImpl(comid, phKey, pbSignature, dwSigLen, phzHash);
	default:
		VarLogEntry(" signatureSM2ServiceImpl", "algorithm error", algo, 0);
		return -1;
	}

	return ret;
}

//验签
int verifyService(int comid, PHKEY_Z phKey, const BYTE *pbSignature, DWORD dwSigLen, PHHASH_Z phzHash) {
	int ret = 0;
	int algo;

	algo = atoi((CHAR*)phKey->ALGID);

	//判断算法
	switch (algo)
	{
	case ALGO_RSA:
		ret = verifyRSAServiceImpl(comid, phKey, pbSignature, dwSigLen, phzHash);
	case ALGO_SM2:
		ret = verifySM2ServiceImpl(comid, phKey, pbSignature, dwSigLen, phzHash);
	default:
		VarLogEntry(" verifyService", "algorithm error", algo, 0);
		return -1;
	}

	return ret;
}

//数据hash
int hashDataService(int comid, PHHASH_Z phzHash, const BYTE *pbData, DWORD dwDataLen) {
	int ret = 0;
	int hash_id;

	hash_id = atoi((CHAR*)phzHash->ALGID);

	//MD2 SHA-1 MD5 ..... SM3
	ret = genhash(comid, 0, NULL, hash_id, dwDataLen, (UCHAR*)pbData, (UCHAR*)pbData);
	if (ret != 0) {
		VarLogEntry(" hashDataService", "genhash error", ret, 0);
	}
	return ret;
}

//密钥hash
int hashKeyService(int comid, PHHASH_Z phzHash) {
	int ret = 0;
	int hash_id;

	hash_id = atoi((CHAR*)phzHash->ALGID);

	//MD2 SHA-1 MD5 ..... SM3
	ret = genhash(comid, 0, NULL, hash_id, phzHash->phKey->len, phzHash->phKey->key, phzHash->keyHashValue);
	if (ret != 0) {
		VarLogEntry(" hashDataService", "genhash error", ret, 0);
	}
	return ret;
}

//派生密钥
int derivatekeyService(int comid, PHKEY_Z phKey, ALG_ID Algid, HCRYPTHASH hBaseData) {
	int ret = 0;
	///////////////////////////
	char *key;
	int algo;
	int dataLen;
	int keyLen;
	int encmode = 0;
	char *iv = NULL;
	int derivationmode = 0;
	HKEY_Z *hKey_z;
	CHAR cKey[256];


	hKey_z = phKey;
	algo = Algid;
	key = (CHAR*)phKey->key;
	dataLen = strlen((CHAR*)hBaseData);

	keyLen = strlen(key) / 2;
	PackBCD(key, (unsigned char*)cKey, strlen(key));
	ret = derivatekey(comid, 0, NULL, algo, derivationmode, encmode, (CHAR*)phKey->keyType, (CHAR*)phKey->keyType, keyLen, cKey, dataLen, iv, (CHAR*)hBaseData, 0, NULL, NULL, (char*)phKey->dKey, (char*)phKey->dCv);
	if (ret < 0) {
		VarLogEntry("derivatekey", "error", ret, 0);
		return ret;
	}

	return ret;
}

