#include "stdafx.h"

int initCSP(void){
	char *value = NULL;
	int rv = -1;

	rv = GetConfigString("GMNCSP-DLL", "LoggingLevel", &value);
	if (rv != 0){
		return rv;
	}
	//printf("LoggingLevel ： %s\n",value);
	setLevel(atoi(value));
	if (value != NULL){
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "IP", &value);
	if (rv != 0){
		return rv;
	}
	//printf("IP ： %s\n", value);
	setHsmIP(value);
	if (value != NULL){
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "PORT", &value);
	if (rv != 0){
		return rv;
	}
	//printf("PORT ： %s\n", value);
	setHsmPORT(atoi(value));
	if (value != NULL){
		free(value);
		value = NULL;
	}
	
	rv = GetConfigString("HSM-TOKEN", "CV", &value);
	if (rv != 0){
		return rv;
	}
	//printf("CV ： %s\n", value);
	setHsmCV(value);
	if (value != NULL){
		free(value);
		value = NULL;
	}
	
	VarLogEntry("initCSP", "IP:%s PORT:%d Level:%d CV:%s", rv, 1,
		getHsmIP(), getHsmPORT(), getLevel(), getHsmCV());

	/*
	printf("LoggingLevel ： %d\n",getLevel());
	printf("IP ： %s\n", getIP());
	printf("PORT ： %d\n", getPORT());
	printf("CV ： %s\n", getCV());
	*/

	return rv;
}

int testSjl22(void){
	int ret = -1;
	int cmdid;

	//开启连接
	cmdid = InitHsmDevice(getHsmIP(),getHsmPORT(),0);
	if (cmdid < 0) {
		VarLogEntry("InitHsmDevice", " error IP:%s PORT:%d", cmdid, 0,
			getHsmIP(), getHsmPORT());
		return cmdid;
	}

	ret = testHSM(cmdid, 0, NULL, getHsmCV(), NULL);
	if (ret != 0) {
		VarLogEntry("InitHsmDevice", " error CHECKVALUE: %s", cmdid, 0,
			getHsmCV());
		return ret;
	}

	//关闭连接
	CloseHsmDevice(cmdid);
	return ret;
}

int genrsakeyImpl(DWORD dwFlags, HPKEY_Z *pKey, int comid) {
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
	int ret;
	UCHAR * key;

	int public_key_encoding = 1;
	ret = genrsakey(comid, 0, NULL,
		key_usage, mode_flag, 
		key_length, public_key_encoding,
		public_exponent_len,public_exponent,
		99,0,NULL,
		public_key,&public_key_len,mac,
		private_key,&private_key_len,
		NULL, NULL, NULL, NULL,NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL,NULL, NULL, NULL, NULL);
	
	if (ret < 0 ) {
		return ret;
	}

	pKey->puLen = public_key_len;
	pKey->pvLen = private_key_len;
	memcpy(pKey->puKey, public_key, public_key_len);
	memcpy(pKey->pvKey, private_key, private_key_len);
	return ret;
}	

int exportrsadeskeyImpl(HCRYPTKEY hKey, HCRYPTKEY hPubKey, UCHAR * data,int * data_length) {
	char * ip = getHsmIP();
	int port = getHsmPORT();
	int timeout = 0;
	int comid;
	int ret;

	comid = InitHsmDevice(ip, port, timeout);
	if (comid < 0) {
		return comid;
	}
	//////////////////////////
	UCHAR * wkLmk = (UCHAR*)hKey;
	UCHAR * public_key = (UCHAR *)hPubKey;
	int  public_key_len;
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

int importrsadeskeyImpl(UCHAR * data, int data_length, UCHAR * private_key, int  private_key_len, UCHAR * wkLmk, int * keylen, UCHAR * cv) {
	int timeout = 0;
	int comid;
	int ret;

	comid = InitHsmDevice(getHsmIP(),getHsmPORT(),timeout);
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

