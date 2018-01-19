#ifndef __API_ZH__
#define __API_ZH__

//A0
int generateKey(int comid, int msghdlen, char *msghd, int algo, int genMod, char *keyType, char keyFlag, char *key, char *checkValue);

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
	char *data);
#endif