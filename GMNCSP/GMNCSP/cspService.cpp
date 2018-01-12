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