/*
 * secret.c
 *
 *  Created on: 2018定7埖10晩
 *      Author: MSI
 */
#include "common.h"

int desECB(void)
{
	printf("DES ECB。\n");
	int rc = 0;
	int len = 0;
	int mode;
	unsigned char key[255];
	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];


	mode = DES_ENCRYPT;
//	mode = DES_DECRYPT;
	memset(in,0,sizeof(in));

	len = 8;
	memset(key,0x11,len);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,key,len);
	rc = desEcbEncryptSingle(key,in,out,mode);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,8);
	rc = desEcbEncryptSingle(key,out,out2,mode^1);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,8);

	len = 16;
	memset(key,0x11,len);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,key,len);
	rc = desEcbEncryptDouble(key,in,out,mode);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,8);
	rc = desEcbEncryptSingle(key,out,out2,mode^1);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,8);


	len = 24;
	memset(key,0x11,len);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,key,len);
	rc = desEcbEncryptTriple(key,in,out,mode);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,8);
	rc = desEcbEncryptSingle(key,out,out2,mode^1);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,8);


	return rc;
}

int desCBC(void)
{
	printf("DES CBC。\n");
	int rc = 0;
	int len = 0;
	int iLen = 8;
	unsigned char key[255];
	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];
	unsigned char iv[8];


	memset(in,0x11,sizeof(in));
	memset(iv,0x11,sizeof(iv));

	len = 8;
	memset(key,0x11,len);
	printf("KEY:\n");
	HexDumpBuffer(stderr,key,len);
	rc = desCbcEncryptSingle(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText RC:%d\n",rc);
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	printf("PlainText:\n");
	rc = desCbcEncryptSingle(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 16;
	iLen = 24;
	memset(key,0x11,len);
	desCbcEncryptDouble(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	desCbcEncryptDouble(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 24;
	iLen = 24;
	memset(key,0x11,len);
	desCbcEncryptTriple(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	desCbcEncryptTriple(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	return rc;
}

int desCFB(void)
{
	printf("DES CFB。\n");
	int rc = 0;
	int len = 0;
	int iLen = 8;
	unsigned char key[255];
	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];
	unsigned char iv[8];


	memset(in,0x11,sizeof(in));
	memset(iv,0x11,sizeof(iv));
	printf("IV:\n");
	HexDumpBuffer(stderr,iv,8);
	printf("DATA:\n");
	HexDumpBuffer(stderr,in,8);

	len = 8;
	memset(key,0x11,len);
	printf("KEY:\n");
	HexDumpBuffer(stderr,key,len);
	rc = desCfbEncryptSingle(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	printf("PlainText:\n");
	rc = desCfbEncryptSingle(key,out,iLen,out2,iv,DES_DECRYPT);
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 16;
	iLen = 16;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	desCfbEncryptDouble(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	desCfbEncryptDouble(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 24;
	iLen = 24;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	desCfbEncryptTriple(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	desCfbEncryptTriple(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	return rc;
}

int desOFB(void)
{
	printf("DES OFB。\n");
	int rc = 0;
	int len = 0;
	int iLen = 8;
	unsigned char key[255];
	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];
	unsigned char iv[8];


	memset(in,0x11,sizeof(in));
	memset(iv,0x11,sizeof(iv));
	printf("IV:\n");
	HexDumpBuffer(stderr,iv,8);
	printf("DATA:\n");
	HexDumpBuffer(stderr,in,8);

	len = 8;
	memset(key,0x11,len);
	printf("KEY:\n");
	HexDumpBuffer(stderr,key,len);
	rc = desOfbEncryptSingle(key,in,iLen,out,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	printf("PlainText:\n");
	rc = desOfbEncryptSingle(key,out,iLen,out2,iv);
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 16;
	iLen = 16;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	desOfbEncryptDouble(key,in,iLen,out,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	desOfbEncryptDouble(key,out,iLen,out2,iv);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 24;
	iLen = 24;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	desOfbEncryptTriple(key,in,iLen,out,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	desOfbEncryptTriple(key,out,iLen,out2,iv);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	return rc;
}

int main(int argc, char **argv)
{
	printf("\n hello OPENSSL.\n");
	desECB();
	desCBC();
	desCFB();
	desOFB();
	return 0;
}
