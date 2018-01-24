#include "stdafx.h"


//initialize
int initCspServiceImpl(void) {
	char *value = NULL;
	int rv = -1;

	rv = GetConfigString("GMNCSP-DLL", "LoggingLevel", &value);
	if (rv != 0) {
		return rv;
	}
	setLevel(atoi(value));
	if (value != NULL) {
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "IP", &value);
	if (rv != 0) {
		return rv;
	}
	setHsmIP(value);
	if (value != NULL) {
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "PORT", &value);
	if (rv != 0) {
		return rv;
	}
	setHsmPORT(atoi(value));
	if (value != NULL) {
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "CV", &value);
	if (rv != 0) {
		return rv;
	}
	setHsmCV(value);
	if (value != NULL) {
		free(value);
		value = NULL;
	}

	VarLogEntry("initCspServiceImpl", "IP:%s PORT:%d Level:%d CV:%s", rv, 1,
		getHsmIP(), getHsmPORT(), getLevel(), getHsmCV());

	return rv;
}

//匹配序列号
int testSjl22ServiceImpl(void) {
	int ret = -1;
	int comid;

	//开启连接
	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), 0);
	if (comid < 0) {
		VarLogEntry("InitHsmDevice", " error IP:%s PORT:%d", comid, 0,
			getHsmIP(), getHsmPORT());
		return comid;
	}

	ret = testHSM(comid, 0, NULL, getHsmCV(), NULL);
	if (ret != 0) {
		VarLogEntry("InitHsmDevice", " error CHECKVALUE: %s", comid, 0,
			getHsmCV());
		return ret;
	}

	//关闭连接
	CloseHsmDevice(comid);
	return ret;
}

//生成对称密钥
int generateKeyServiceImpl(int comid, PHKEY_Z  hKey, int algo) {
	char key[255];
	char checkValue[6 + 1];
	int genMod;
	genMod = 0;
	int ret = 0;
	char * keyType = ZEK_TYPE;

	ret = generateKey(comid, 0, NULL, algo, genMod, keyType, 'X', key, checkValue);
	if (ret<0) {
		VarLogEntry(" CPGenKey", "DES/TDES error", ret, 0);
		return ret;
	}
	hKey = (HKEY_Z*)malloc(sizeof(HKEY_Z));
	if (NULL == hKey) {
		VarLogEntry(" CPGenKey", "memory error", -1, 0);
		return -1;
	}
	hKey->len = strlen(key);
	memcpy(hKey->key, key, hKey->len);
	memcpy(hKey->cv, checkValue, strlen(checkValue));
	sprintf((CHAR*)hKey->ALGID, "%02d", algo);
	sprintf((CHAR*)hKey->KEYLEN, "%04d", hKey->len);
	memcpy(hKey->keyType, keyType, strlen(keyType));
	return ret;
}

//生成RSA密钥
int genrsakeyServiceImpl(HCRYPTPROV hProv, DWORD dwFlags, PHPKEY_Z pKey, int comid, int Algid) {
	int key_usage = 2;
	int mode_flag = 0;
	int key_length = 2048;
	int public_exponent_len = 32;
	UCHAR public_exponent[] = { 0x00,0x01,0x00,0x01 };
	UCHAR public_key[4096];
	int  public_key_len;
	UCHAR mac[16];
	UCHAR private_key[4096];
	int  private_key_len;
	int ret = 0;

	int public_key_encoding = 1;
	ret = genrsakey(comid, 0, NULL,
		key_usage, mode_flag,
		key_length, public_key_encoding,
		public_exponent_len, public_exponent,
		99, 0, NULL,
		public_key, &public_key_len, mac,
		private_key, &private_key_len,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	if (ret < 0) {
		VarLogEntry("CPGenKey", "RSA GENERATE error", ret, 0);
		return ret;
	}

	pKey = (HPKEY_Z*)malloc(sizeof(HPKEY_Z));
	if (NULL == pKey) {
		VarLogEntry("CPGenKey", "memory error", -1, 0);
		return -1;
	}

	pKey->puLen = public_key_len;
	pKey->pvLen = private_key_len;
	memcpy(pKey->puKey, public_key, public_key_len);
	memcpy(pKey->pvKey, private_key, private_key_len);
	sprintf((CHAR*)pKey->ALGID, "%02d", Algid);

	/*
	从密钥容器中获取已持久化的用户密钥句柄:从容器中获取RSA的密钥文件ID标识和。
	dwKeySpec phUserKey 根据密钥属性获取密钥句柄
	1. AT_KEYEXCHANGE 交换密钥
	2. AT_SIGNATURE 签名密钥
	*/
	if (NULL != dwFlags) {
		switch (dwFlags)
		{
		case AT_KEYEXCHANGE:
			ret = cpSetProvParamImpl(hProv, AT_KEYEXCHANGE, (BYTE *)pKey, REG_BINARY);
			if (ERROR_SUCCESS != ret) {
				VarLogEntry(" genrsakeyServiceImpl", "AT_KEYEXCHANGE error", ret, 0);
			}
			break;
		case AT_SIGNATURE:
			ret = cpSetProvParamImpl(hProv, AT_SIGNATURE, (BYTE *)pKey, REG_BINARY);
			if (ERROR_SUCCESS != ret) {
				VarLogEntry(" genrsakeyServiceImpl", "AT_SIGNATURE error", ret, 0);
			}
			break;
		default:
			break;
		}
	}

	return ret;
}

//生成SM2密钥
int genSm2KeyServiceImpl(PHKEY_Z hKey, int comid, int Algid) {
	int ret = 0;

	///////////////////////////
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

	///////////////////////////////////////////

	char * ip = getHsmIP();
	int port = getHsmPORT();
	int timeout = 0;

	ret = gensm2key(comid, msghdlen, msghd, algflag, key_usage, compflag, key_length, index, Plen, Pbuf, Alen, Abuf, Blen,
		Bbuf, Gxlen, Gxbuf, Gylen, Gybuf, Nlen, Nbuf, puKey, &puLen, pvKey, &pvLen, deKey, &deLen);
	if (ret != 0) {
		VarLogEntry(" genSm2KeyServiceImpl", "gensm2key error", ret, 0);
		return -1;
	}
	hKey = (PHKEY_Z)malloc(sizeof(HKEY_Z));
	if (NULL == hKey) {
		VarLogEntry(" genSm2KeyServiceImpl", "Memory error", ret, 0);
		return -1;
	}
	sprintf((CHAR*)hKey->ALGID, "%02d", Algid);
	memcpy(puKey, hKey->puKey, puLen);
	memcpy(pvKey, hKey->pvKey, pvLen);
	memcpy(deKey, hKey->derPuKey, deLen);
	hKey->puLen = puLen;
	hKey->pvLen = pvLen;
	hKey->derPuLen = deLen;
	return ret;
}

//
int getKeyParamServiceImpl(CHAR * data, LPBYTE pbData, LPDWORD pcbDataLen) {
	int ret = 0;

	*pcbDataLen = strlen(data);
	if (pcbDataLen <= 0) {
		return  -1;
	}

	if (NULL != pbData) {
		memcpy(pbData, data, *pcbDataLen);
	}

	return ret;
}

//
int verifyRSAServiceImpl(int comid, PHKEY_Z phKey, const BYTE *pbSignature, DWORD dwSigLen, PHHASH_Z phzHash) {
	int ret = 0;
	//RSA 01 SM2 03
	int sign_id = 01;
	//RSA 123456 SM2 00
	int pad_mode = 01;
	///////////////////////////////////////////////
	int msghdlen = 0;
	char *msghd = NULL;
	int hash_id;
	int mgfHash = NULL;
	int OAEP_parm_len = NULL;
	UCHAR *OAEP_parm = NULL;
	int pssRule = NULL;
	int trailerField = NULL;
	int index = 99;
	int authenDataLen = 0;
	UCHAR * authenData = NULL;

	hash_id = atoi((CHAR*)phzHash->ALGID);
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
		phzHash->sigLen,
		phzHash->signature,
		index,
		NULL,
		phKey->puKey,
		phKey->puLen,
		authenDataLen,
		authenData
	);
	if (0 != ret) {
		VarLogEntry(" verifyRSAServiceImpl", "rsapubverify error", ret, 0);
		return ret;
	}
	return ret;
}

//
int verifySM2ServiceImpl(int comid, PHKEY_Z phKey, const BYTE *pbSignature, DWORD dwSigLen, PHHASH_Z phzHash) {
	int ret = 0;
	//RSA 01 SM2 03
	int sign_id = 3;
	//RSA 123456 SM2 00
	int pad_mode = 0;
	///////////////////////////////////////////////
	int msghdlen = 0;
	char *msghd = NULL;
	int hash_id;
	int mgfHash = NULL;
	int OAEP_parm_len = NULL;
	UCHAR *OAEP_parm = NULL;
	int pssRule = NULL;
	int trailerField = NULL;
	int index = 99;
	int authenDataLen = 0;
	UCHAR * authenData = NULL;

	hash_id = atoi((CHAR*)phzHash->ALGID);
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
		phzHash->sigLen,
		phzHash->signature,
		index,
		NULL,
		phKey->puKey,
		phKey->puLen,
		authenDataLen,
		authenData
	);
	if (0 != ret) {
		VarLogEntry(" verifySM2ServiceImpl", "rsapubverify error", ret, 0);
		return ret;
	}
	return ret;
}

//
int signatureRSAServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbSignature, DWORD *dwSigLen, PHHASH_Z phzHash) {
	int ret = 0;

	//RSA 01 SM2 03
	int sign_id = 01;
	//RSA 123456 SM2 00
	int pad_mode = 01;
	///////////////////////////////////////////////
	int msghdlen = 0;
	char *msghd = NULL;
	int mgfHash = NULL;
	int OAEP_parm_len = NULL;
	UCHAR *OAEP_parm = NULL;
	int pssRule = NULL;
	int trailerField = NULL;
	int index = 99;
	int hash_id;

	hash_id = atoi((CHAR*)phzHash->ALGID);
	ret = rsaprisign(comid, msghdlen, msghd, hash_id,
		sign_id,
		pad_mode,
		mgfHash,
		OAEP_parm_len,
		OAEP_parm,
		pssRule,
		trailerField,
		*dwSigLen,
		pbSignature,
		index,
		phKey->pvLen,
		phKey->pvKey,
		phzHash->signature,
		&phzHash->sigLen);
	if (ret < 0) {
		VarLogEntry(" signatureRSAServiceImpl", "rsaprisign error", ret, 0);
	}
	return ret;
}

//
int signatureSM2ServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbSignature, DWORD *dwSigLen, PHHASH_Z phzHash) {
	int ret = 0;

	//RSA 01 SM2 03
	int sign_id = 3;
	//RSA 123456 SM2 00
	int pad_mode = 0;
	///////////////////////////////////////////////
	int msghdlen = 0;
	char *msghd = NULL;
	int mgfHash = NULL;
	int OAEP_parm_len = NULL;
	UCHAR *OAEP_parm = NULL;
	int pssRule = NULL;
	int trailerField = NULL;
	int index = 99;
	int hash_id;

	hash_id = atoi((CHAR*)phzHash->ALGID);
	ret = rsaprisign(comid, msghdlen, msghd, hash_id,
		sign_id,
		pad_mode,
		mgfHash,
		OAEP_parm_len,
		OAEP_parm,
		pssRule,
		trailerField,
		*dwSigLen,
		pbSignature,
		index,
		phKey->pvLen,
		phKey->pvKey,
		phzHash->signature,
		&phzHash->sigLen);
	if (ret < 0) {
		VarLogEntry(" signatureSM2ServiceImpl", "rsaprisign error", ret, 0);
	}
	return ret;
}

//
int encryptRSAServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	/////////////////////////////
	int msghdlen = 0;
	char * msghd = NULL;
	int mgfHash = 0;
	int OAEP_parm_len = 0;
	UCHAR *OAEP_parm = NULL;
	int index = 99;
	UCHAR *mac = NULL;
	int authenDataLen = 0;
	UCHAR *authenData = NULL;
	////////////////////////////
	//RSA 1 SM2 3
	int sig_alg = 1;
	//0加密   1解密
	int dec_flag = 0;
	//RSA 1234 SM2 00
	int pad_mode = 1;
	////////////////////////////////
	int sign_length = *pdwDataLen;
	UCHAR * sign = pbData;
	UCHAR *public_key = phKey->puKey;
	int public_key_len = phKey->puLen;

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
		pbData,
		(int *)pdwDataLen
	);
	if (ret != 0) {
		VarLogEntry(" encryptRSAServiceImpl", "rsapubkeyoper error", ret, 0);
	}
	//////////////////////////////////////////////
	return ret;
}

//
int decryptRSAServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;

	/////////////////////////////////////////
	int index = 99;
	int mgfHash = 0;
	int msghdlen = 0;
	int OAEP_parm_len = 0;
	char * msghd = NULL;
	UCHAR *OAEP_parm = NULL;
	////////////////////////////
	//RSA 1 SM2 3
	int sig_alg = 1;
	//0加密   1解密
	int dec_flag = 1;
	//RSA 1234 SM2 00
	int pad_mode = 1;
	//////////////////////////////////
	int data_len = *pdwDataLen;
	UCHAR * data = pbData;
	int private_key_len = phKey->pvLen;
	UCHAR *private_key = phKey->pvKey;

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
		pbData,
		(int *)pdwDataLen);
	//////////////////////////////////////////////
	if (ret != 0) {
		VarLogEntry(" decryptRSAServiceImpl", "rsaprikeyoper error", ret, 0);
	}
	return ret;
}

//
int encryptSM2ServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	/////////////////////////////
	int msghdlen = 0;
	char * msghd = NULL;
	int mgfHash = 0;
	int OAEP_parm_len = 0;
	UCHAR *OAEP_parm = NULL;
	int index = 99;
	UCHAR *mac = NULL;
	int authenDataLen = 0;
	UCHAR *authenData = NULL;
	////////////////////////////
	//RSA 1 SM2 3
	int sig_alg = 3;
	//0加密   1解密
	int dec_flag = 0;
	//RSA 1234 SM2 00
	int pad_mode = 0;
	////////////////////////////////
	int sign_length = *pdwDataLen;
	UCHAR * sign = pbData;
	UCHAR *public_key = phKey->puKey;
	int public_key_len = phKey->puLen;

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
		pbData,
		(int *)pdwDataLen
	);
	if (ret != 0) {
		VarLogEntry(" encryptSM2ServiceImpl", "rsapubkeyoper error", ret, 0);
	}
	//////////////////////////////////////////////
	return ret;
}

//
int decryptSM2ServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;

	/////////////////////////////////////////
	int index = 99;
	int mgfHash = 0;
	int msghdlen = 0;
	int OAEP_parm_len = 0;
	char * msghd = NULL;
	UCHAR *OAEP_parm = NULL;
	////////////////////////////
	//RSA 1 SM2 3
	int sig_alg = 3;
	//0加密   1解密
	int dec_flag = 1;
	//RSA 1234 SM2 00
	int pad_mode = 0;
	//////////////////////////////////
	int data_len = *pdwDataLen;
	UCHAR * data = pbData;
	int private_key_len = phKey->pvLen;
	UCHAR *private_key = phKey->pvKey;

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
		pbData,
		(int *)pdwDataLen);
	//////////////////////////////////////////////
	if (ret != 0) {
		VarLogEntry(" decryptSM2ServiceImpl", "rsaprikeyoper error", ret, 0);
	}
	return ret;
}

//
int encryptDataServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	int algo;
	int dataBlockFlag = 0;
	int encryptFlag;
	int algoOperationMode = 0;
	int inputFormat = 1;
	int outputFormat = 1;
	char * keyType;
	int paddingMode = 0;
	char paddingChar[] = "0000";
	int paddingFlag = 0;
	char *iv = NULL;
	int outFlag;


	//0 加密 1解密
	encryptFlag = 0;
	keyType = (CHAR*)phKey->keyType;
	algo = atoi((CHAR*)phKey->ALGID);

	ret = encryptDecrypt(comid, 0, NULL, algo,
		dataBlockFlag,
		encryptFlag,
		algoOperationMode,
		inputFormat,
		outputFormat,
		keyType,
		(CHAR*)phKey->key,
		paddingMode,
		paddingChar,
		paddingFlag,
		iv,
		&outFlag,
		(int*)pdwDataLen,
		(CHAR*)pbData);
	if (ret < 0) {
		VarLogEntry(" encryptDataServiceImpl", " error", ret, 0);
		return ret;
	}
	return ret;
}

//
int decryptDataServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen) {
	int ret = 0;
	int algo;
	int dataBlockFlag = 0;
	int encryptFlag;
	int algoOperationMode = 0;
	int inputFormat = 1;
	int outputFormat = 1;
	char * keyType;
	int paddingMode = 0;
	char paddingChar[] = "0000";
	int paddingFlag = 0;
	char *iv = NULL;
	int outFlag;

	//0 加密 1解密
	encryptFlag = 1;
	keyType = (CHAR*)phKey->keyType;
	algo = atoi((CHAR*)phKey->ALGID);

	ret = encryptDecrypt(comid, 0, NULL, algo,
		dataBlockFlag,
		encryptFlag,
		algoOperationMode,
		inputFormat,
		outputFormat,
		keyType,
		(CHAR*)phKey->key,
		paddingMode,
		paddingChar,
		paddingFlag,
		iv,
		&outFlag,
		(int *)pdwDataLen,
		(CHAR*)pbData);
	if (ret < 0) {
		VarLogEntry(" decryptDataServiceImpl", "error", ret, 0);
	}
	return ret;
}

//
int importrsadeskeyServiceImpl(UCHAR * data, int data_length, UCHAR * private_key, int  private_key_len, UCHAR * wkLmk, int * keylen, UCHAR * cv) {
	int timeout = 0;
	int comid;
	int ret = 0;

	comid = InitHsmDevice(getHsmIP(), getHsmPORT(), timeout);
	if (comid < 0) {
		return comid;
	}
	//////////////////////////
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
	int keyTypeMode = 0;
	UCHAR keyType[] = ZPK_TYPE;
	int index = 99;
	UCHAR *mac = NULL;
	int authenDataLen = NULL;
	UCHAR *authenData = NULL;
	UCHAR *iv = NULL;
	CHAR lmkSchem = 'X';
	CHAR cvFlag = 0;

	__try {
		ret = importrsadeskey(
			comid,
			msghdlen, msghd,
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
			keyTypeMode,
			keyType,
			data_length,
			data,
			index,
			private_key_len,
			private_key,
			lmkSchem,
			cvFlag,
			iv,
			cv,
			wkLmk,
			keylen
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

