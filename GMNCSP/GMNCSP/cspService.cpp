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

int genrsakeyImpl(DWORD dwFlags, HCRYPTKEY *phKey, int comid) {
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

	switch (dwFlags)
	{
	case PUBLICKEYBLOB:
		key = (UCHAR *)malloc(public_key_len);
		if (NULL == key) {
			return -1;
		}
		memcpy(key, public_key, public_key_len);
		break;
	case PRIVATEKEYBLOB:
		key = (UCHAR *)malloc(private_key_len);
		if (NULL == key) {
			return -1;
		}
		memcpy(key, private_key, private_key_len);
		break;
	default:
		return -163;
	}
	*phKey = (ULONG)key;
	return ret;
}	