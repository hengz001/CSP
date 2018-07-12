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

int aes_encrypt(void)
{
	printf("-----> AES\n");
	int rc = 0;
	unsigned char userKey[255];
	int bits;
	AES_KEY aesKey;

	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];

	memset(in,0,sizeof(in));
	memset(userKey,0,sizeof(userKey));

//////////////////////////////////////128
	bits = 128;
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = generateAesKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192
	bits = 192;
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = generateAesKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = generateAesKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

	return rc;
}

int aes_cbc_encrypt(void)
{
	printf("-----> AES CBC\n");
	int rc = 0;
	unsigned char userKey[255];
	int bits;
	AES_KEY aesKey;

	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];
	unsigned char iv[255];

	memset(in,0,sizeof(in));
	memset(iv,0x11,sizeof(iv));
	memset(userKey,0,sizeof(userKey));

//////////////////////////////////////128
	bits = 128;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	rc = aesCbcEncrypt(in,out,bits/8,&aesKey,iv,AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = generateAesKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = aesCbcEncrypt(out,out2,bits/8,&aesKey,iv,AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192
	bits = 192;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = aesCbcEncrypt(in,out,bits/8,&aesKey,iv,AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = generateAesKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = aesCbcEncrypt(out,out2,bits/8,&aesKey,iv,AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = aesCbcEncrypt(in,out,bits/8,&aesKey,iv,AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = generateAesKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = aesCbcEncrypt(out,out2,bits/8,&aesKey,iv,AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

	return rc;
}

int aes_cfb_encrypt(void)
{
	printf("-----> AES CFB\n");
	int rc = 0;
	unsigned char userKey[255];
	int bits;
	AES_KEY aesKey;

	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];
	unsigned char iv[255];

	memset(in,0,sizeof(in));
	memset(iv,0x11,sizeof(iv));
	memset(userKey,0,sizeof(userKey));

//////////////////////////////////////128
	bits = 128;
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesCfbEncrypt(in,out,bits,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesCfbEncrypt(out,out2,bits,&aesKey,iv,AES_DECRYPT);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192

	bits = 192;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesCfbEncrypt(in,out,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesCfbEncrypt(out,out2,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesCfbEncrypt(in,out,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out,16);
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesCfbEncrypt(out,out2,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out2,16);

	return rc;
}

int aes_ofb_encrypt(void)
{
	printf("-----> AES CFB\n");
	int rc = 0;
	unsigned char userKey[255];
	int bits;
	AES_KEY aesKey;

	unsigned char in[255];
	unsigned char out[255];
	unsigned char out2[255];
	unsigned char iv[255];

	memset(in,0,sizeof(in));
	memset(iv,0x11,sizeof(iv));
	memset(userKey,0,sizeof(userKey));

//////////////////////////////////////128
	bits = 128;
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesOfbEncrypt(in,out,bits,&aesKey,iv);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesOfbEncrypt(out,out2,bits,&aesKey,iv);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192

	bits = 192;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesOfbEncrypt(in,out,128,&aesKey,iv);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesOfbEncrypt(out,out2,128,&aesKey,iv);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesOfbEncrypt(in,out,128,&aesKey,iv);
	HexDumpBuffer(stderr,out,16);
	memset(iv,0x11,sizeof(iv));
	rc = generateAesKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = aesOfbEncrypt(out,out2,128,&aesKey,iv);
	HexDumpBuffer(stderr,out2,16);

	return rc;
}

int rsaView(void)
{
	int rc = 0;
	printf("--------------------> RSA\n");
	RSA *puKey,*prKey;

	puKey = RSA_new();
	prKey = RSA_new();

	rc = generateRsaKey(1024,65537,puKey,prKey);
	printf("RC:%d\n",rc);
	RSA_print_fp(stdout,prKey,0);
	PEM_write_RSAPublicKey(stdout,puKey);
	PEM_write_RSAPrivateKey(stdout,prKey,NULL,NULL,0,NULL,NULL);

	unsigned char m[] = "zhuheng";
	unsigned int m_length = sizeof(m);
	unsigned char sigBuf[1024];
	unsigned int sigLen = 0;
	int hashType = NID_md5;

	rc = rsaSign(hashType,m,m_length,sigBuf,&sigLen,prKey);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stdout,sigBuf,sigLen);

	rc = rsaVerify(hashType,m,m_length,sigBuf,sigLen,puKey);
	printf("RC:%d\n",rc);

	unsigned char out1[1024];
	unsigned char out2[1024];
	int olen1;
	int olen2;

	 olen1 = rsaPublicKeyEncrypt(m_length,m,out1,puKey,RSA_PKCS1_PADDING);
	 printf("\n CipherText length:%d\n",olen1);
	 HexDumpBuffer(stdout,out1,olen1);

	 olen2 = rsaPrivateKeyDecrypt(olen1,out1,out2,prKey,RSA_PKCS1_PADDING);
	 printf("\n PlainText length:%d\n",olen2);
	 HexDumpBuffer(stdout,out2,olen2);

	 olen1 = rsaPrivateKeyEncrypt(m_length,m,out1,prKey,RSA_PKCS1_PADDING);
	 printf("\n CipherText length:%d\n",olen1);
	 HexDumpBuffer(stdout,out1,olen1);

	 olen2 = rsaPublicKeyDecrypt(olen1,out1,out2,puKey,RSA_PKCS1_PADDING);
	 printf("\n PlainText length:%d\n",olen2);
	 HexDumpBuffer(stdout,out2,olen2);

	RSA_free(puKey);
	RSA_free(prKey);
	return rc;
}

int main(int argc, char **argv)
{
	printf("\n hello OPENSSL.\n");

	//DES
//	desECB();
//	desCBC();
//	desCFB();
//	desOFB();

	//AES
//	aes_encrypt();
//	aes_cbc_encrypt();
//	aes_cfb_encrypt();
//	aes_ofb_encrypt();

	//RSA
	rsaView();

	return 0;
}
