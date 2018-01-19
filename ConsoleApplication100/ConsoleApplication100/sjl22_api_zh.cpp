#include "stdafx.h"

//A0
int generateKey(int comid, int msghdlen, char *msghd, int algo, int genMod, char *keyType, char keyFlag, char *key, char *checkValue) {
	int ret = 0;
	char *cmd, *p;
	int cmdLen, rspLen;
	char rsp[MAX_MSGDATA + 1];
	int keyLen;

	if (comid<0) {
		return (-1);
	}
	cmd = (char *)malloc(msghdlen
		+ 2	//command head
		+ 3	//alog PXX
		+ 1	//generate mode 0
		+ 3	//key type 000
		+ 1	//key flag XYZ X
		+ 1);	//0x00
	if (NULL == cmd) {
		return (-1);
	}
	p = cmd;
	*p++ = 'A';
	*p++ = '0';
	*p++ = 'P';
	*p++ = algo + '0';
	*p++ = algo + '0';
	*p++ = genMod + '0';
	memcpy(p, keyType, 3);
	p += 3;
	*p++ = keyFlag;
	*p = 0x00;
	cmdLen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdLen, (char *)rsp, &rspLen);
	free(cmd);

	if (ret<0) {
		return (ret);
	}

	p = rsp;

	switch (*p)
	{
	case 'Z':
		keyLen = 16;
	case 'U':
	case 'X':
	case 'S': //for SM4 2017/5/31 add
		keyLen = 32;
	case 'T':
	case 'Y':
		keyLen = 48;
	default:
		keyLen = 16;
	}
	p++;

	keyLen = (keyLen * 2);

	if (NULL != key) {
		memcpy(key, p, keyLen);
		*(key + keyLen) = 0x00;
	}
	p += keyLen;

	if (NULL != checkValue) {
		memcpy(checkValue, p, 6);
		*(checkValue + 6) = 0x00;
	}

	return ret;
}

//E0
int encryptDecrypt(int comid, int msghdlen, char *msghd, int algo,
	int dataBlockFlag,
	int encryptFlag,
	int algoOperationMode,
	int inputFormat,
	int outputFormat,
	char *keyType,
	char *key,
	int paddingMode,
	char * paddingChar,
	int paddingFlag,
	char *iv,
	int *outFlag,
	int * dataLen,
	char *data) 
{
	int ret = 0;
	char *cmd, *p;
	int cmdLen, rspLen;
	char rsp[MAX_MSGDATA + 1];
	int keyLen;
	char cLen[4+1];

	keyLen = strlen(key);
	if (comid<0) {
		return (-1);
	}
	cmd = (char *)malloc(msghdlen
		+2
		+3
		+1
		+1
		+2
		+1
		+1
		+3
		+49
		+1
		+4
		+1
		+32
		+4
		+*dataLen
		+ 1);	//0x00
	if (NULL == cmd) {
		return (-1);
	}
	

	p = cmd;
	*p++ = 'E';
	*p++ = '0';
	*p++ = 'P';
	*p++ = algo + '0';
	*p++ = algo + '0';
	*p++ = dataBlockFlag + '0';
	*p++ = encryptFlag + '0';
	sprintf(p,"%02d", algoOperationMode);
	p += 2;
	*p++ = inputFormat + '0';
	*p++ = outputFormat + '0';
	memcpy(p,keyType,3);
	p += 3;
	memcpy(p,key,keyLen);
	p += keyLen;
	*p++ = paddingMode + '0';
	memcpy(p,paddingChar,4);
	p += 4;
	*p++ = paddingFlag + '0';
	if (NULL != iv) {
		int ivLen = strlen(iv);
		memcpy(p, iv, ivLen);
		p += ivLen;
	}
	
	sprintf(p,"%04X",*dataLen);
	p += 4;

	memcpy(p,data,*dataLen*2);
	p += *dataLen*2;
	*p = 0x00;

	cmdLen = p - cmd;

	ret = HsmCmdRun(comid, msghdlen, msghd, (char *)cmd, cmdLen, (char *)rsp, &rspLen);
	free(cmd);

	if (ret<0) {
		return (ret);
	}

	p = rsp;
	*outFlag = *p - '0';
	p++;
	memcpy(cLen,p,4);
	p += 4;
	cLen[4] = 0x00;
	*dataLen = atoi(cLen);
	memcpy(data,p,*dataLen*2);
	p += *dataLen*2;

	return ret;
}
