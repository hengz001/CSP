#include "stdafx.h"

int initCSP(void){
	char *value = NULL;
	int rv = -1;

	rv = GetConfigString("GMNCSP-DLL", "LoggingLevel", &value);
	if (rv != 0){
		return rv;
	}
	//printf("LoggingLevel £º %s\n",value);
	setLevel(atoi(value));
	if (value != NULL){
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "IP", &value);
	if (rv != 0){
		return rv;
	}
	//printf("IP £º %s\n", value);
	setIP(value);
	if (value != NULL){
		free(value);
		value = NULL;
	}

	rv = GetConfigString("HSM-TOKEN", "PORT", &value);
	if (rv != 0){
		return rv;
	}
	//printf("PORT £º %s\n", value);
	setPORT(atoi(value));
	if (value != NULL){
		free(value);
		value = NULL;
	}
	
	rv = GetConfigString("HSM-TOKEN", "CV", &value);
	if (rv != 0){
		return rv;
	}
	//printf("CV £º %s\n", value);
	setCV(value);
	if (value != NULL){
		free(value);
		value = NULL;
	}
	
	VarLogEntry("initCSP", "IP:%s PORT:%d Level:%d CV:%s", rv, 3,
		getIP(), getPORT(), getLevel(), getCV());

	/*
	printf("LoggingLevel £º %d\n",getLevel());
	printf("IP £º %s\n", getIP());
	printf("PORT £º %d\n", getPORT());
	printf("CV £º %s\n", getCV());
	*/

	return rv;
}

int testSjl22(void){
	int timeout = 1000 * 6;
	int fd = -1;
	int rv = -1;
	char rsp[1024*6];
	int rsplen = sizeof(rsp);

	fd = InitHsmDevice(getIP(), getPORT(), timeout);
	if (fd < 0){
		LogEntry("testSjl22", "connect error", fd, 1);
		return fd;
	}

	rv = HsmCmdRun(fd, NULL, NULL, "NC", strlen("NC"), rsp, &rsplen);
	if (rv != 0){
		LogEntry("testSjl22", "HsmCmdRun error", rv, 1);
		return rv;
	}
	//printf("RSP : %s",rsp);
	if (memcmp(rsp,getCV(),16)!= 0){
		LogEntry("testSjl22", "CV error", -1, 1);
		return -1;
	}
	return rv;
}