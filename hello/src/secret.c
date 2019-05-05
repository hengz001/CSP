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
	rc = hzDesEcbEncryptSingle(key,in,out,mode);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,8);
	rc = hzDesEcbEncryptSingle(key,out,out2,mode^1);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,8);

	len = 16;
	memset(key,0x11,len);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,key,len);
	rc = hzDesEcbEncryptDouble(key,in,out,mode);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,8);
	rc = hzDesEcbEncryptSingle(key,out,out2,mode^1);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,8);


	len = 24;
	memset(key,0x11,len);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,key,len);
	rc = hzDesEcbEncryptTriple(key,in,out,mode);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,8);
	rc = hzDesEcbEncryptSingle(key,out,out2,mode^1);
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
	rc = hzDesCbcEncryptSingle(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText RC:%d\n",rc);
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	printf("PlainText:\n");
	rc = hzDesCbcEncryptSingle(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 16;
	iLen = 24;
	memset(key,0x11,len);
	hzDesCbcEncryptDouble(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	hzDesCbcEncryptDouble(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 24;
	iLen = 24;
	memset(key,0x11,len);
	hzDesCbcEncryptTriple(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	hzDesCbcEncryptTriple(key,out,iLen,out2,iv,DES_DECRYPT);
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
	rc = hzDesCfbEncryptSingle(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	printf("PlainText:\n");
	rc = hzDesCfbEncryptSingle(key,out,iLen,out2,iv,DES_DECRYPT);
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 16;
	iLen = 16;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	hzDesCfbEncryptDouble(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	hzDesCfbEncryptDouble(key,out,iLen,out2,iv,DES_DECRYPT);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 24;
	iLen = 24;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	hzDesCfbEncryptTriple(key,in,iLen,out,iv,DES_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	hzDesCfbEncryptTriple(key,out,iLen,out2,iv,DES_DECRYPT);
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
	rc = hzDesOfbEncryptSingle(key,in,iLen,out,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	printf("PlainText:\n");
	rc = hzDesOfbEncryptSingle(key,out,iLen,out2,iv);
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 16;
	iLen = 16;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	hzDesOfbEncryptDouble(key,in,iLen,out,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	hzDesOfbEncryptDouble(key,out,iLen,out2,iv);
	printf("-PlainText:\n");
	HexDumpBuffer(stderr,out2,iLen);

	memset(iv,0x11,sizeof(iv));
	len = 24;
	iLen = 24;
	memset(iv,0x11,sizeof(iv));
	memset(key,0x11,len);
	hzDesOfbEncryptTriple(key,in,iLen,out,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stderr,out,iLen);

	memset(iv,0x11,sizeof(iv));
	hzDesOfbEncryptTriple(key,out,iLen,out2,iv);
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
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = hzAesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = hzAesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192
	bits = 192;
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = hzAesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = hzAesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = hzAesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

	rc = hzAesEncrypt(out, out2, &aesKey, AES_DECRYPT);
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
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	rc = hzAesCbcEncrypt(in,out,bits/8,&aesKey,iv,AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesCbcEncrypt(out,out2,bits/8,&aesKey,iv,AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192
	bits = 192;
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesCbcEncrypt(in,out,bits/8,&aesKey,iv,AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesCbcEncrypt(out,out2,bits/8,&aesKey,iv,AES_DECRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(in, out, &aesKey, AES_ENCRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesCbcEncrypt(in,out,bits/8,&aesKey,iv,AES_ENCRYPT);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stderr,out,16);

	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_DECRYPT);
	printf("RC:%d\n",rc);
//	HexDumpBuffer(stderr,(unsigned char*)&aesKey,sizeof(AES_KEY));

//	rc = aesEncrypt(out, out2, &aesKey, AES_DECRYPT);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesCbcEncrypt(out,out2,bits/8,&aesKey,iv,AES_DECRYPT);
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
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesCfbEncrypt(in,out,bits,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesCfbEncrypt(out,out2,bits,&aesKey,iv,AES_DECRYPT);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192

	bits = 192;
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesCfbEncrypt(in,out,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesCfbEncrypt(out,out2,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesCfbEncrypt(in,out,128,&aesKey,iv,AES_ENCRYPT);
	HexDumpBuffer(stderr,out,16);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesCfbEncrypt(out,out2,128,&aesKey,iv,AES_ENCRYPT);
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
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesOfbEncrypt(in,out,bits,&aesKey,iv);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesOfbEncrypt(out,out2,bits,&aesKey,iv);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////192

	bits = 192;
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesOfbEncrypt(in,out,128,&aesKey,iv);
	HexDumpBuffer(stderr,out,16);

	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesOfbEncrypt(out,out2,128,&aesKey,iv);
	HexDumpBuffer(stderr,out2,16);

//////////////////////////////////////256
	bits = 256;
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesOfbEncrypt(in,out,128,&aesKey,iv);
	HexDumpBuffer(stderr,out,16);
	memset(iv,0x11,sizeof(iv));
	rc = hzAesGenerateKey(userKey,bits,&aesKey,AES_ENCRYPT);
	rc = hzAesOfbEncrypt(out,out2,128,&aesKey,iv);
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

	rc = hzRsaGenerateKey(1024,65537,puKey,prKey);
	printf("RC:%d\n",rc);
	RSA_print_fp(stdout,prKey,0);
	PEM_write_RSAPublicKey(stdout,puKey);
	PEM_write_RSAPrivateKey(stdout,prKey,NULL,NULL,0,NULL,NULL);

	unsigned char m[] = "zhuheng";
	unsigned int m_length = sizeof(m);
	unsigned char sigBuf[1024];
	unsigned int sigLen = 0;
	int hashType = NID_md5;

	rc = hzRsaSign(hashType,m,m_length,sigBuf,&sigLen,prKey);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stdout,sigBuf,sigLen);

	rc = hzRsaVerify(hashType,m,m_length,sigBuf,sigLen,puKey);
	printf("RC:%d\n",rc);

	unsigned char out1[1024];
	unsigned char out2[1024];
	int olen1;
	int olen2;

	 olen1 = hzRsaPublicKeyEncrypt(m_length,m,out1,puKey,RSA_PKCS1_PADDING);
	 printf("\n CipherText length:%d\n",olen1);
	 HexDumpBuffer(stdout,out1,olen1);

	 olen2 = hzRsaPrivateKeyDecrypt(olen1,out1,out2,prKey,RSA_PKCS1_PADDING);
	 printf("\n PlainText length:%d\n",olen2);
	 HexDumpBuffer(stdout,out2,olen2);

	 olen1 = hzRsaPrivateKeyEncrypt(m_length,m,out1,prKey,RSA_PKCS1_PADDING);
	 printf("\n CipherText length:%d\n",olen1);
	 HexDumpBuffer(stdout,out1,olen1);

	 olen2 = hzRsaPublicKeyDecrypt(olen1,out1,out2,puKey,RSA_PKCS1_PADDING);
	 printf("\n PlainText length:%d\n",olen2);
	 HexDumpBuffer(stdout,out2,olen2);

	RSA_free(puKey);
	RSA_free(prKey);
	return rc;
}

int md5View(void)
{
	printf("----> MD5\n");
	int rc = 0;
	unsigned char from[] = "zhuheng";
	int flen = sizeof(from);
	unsigned char to[255];

	rc = hzMD5(from,flen,to);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stdout,to,MD5_DIGEST_LENGTH);

	return rc;
}

int sm3View(void)
{
	printf("-----> SM3\n");
	int rc = 0;
	unsigned char from[] = "zhuheng";
	int flen = sizeof(from);
	unsigned char to[255];

	rc = hzSM3(from,flen,to);
	printf("RC:%d\n",rc);
	HexDumpBuffer(stdout,to,SM3_DIGEST_LENGTH);
	return rc;
}

int sm4View(void)
{
	int rc = 0;
	sms4_key_t enKey;
	sms4_key_t deKey;
	unsigned char userKey[16];
	unsigned char in[256];
	unsigned char out[256];
	unsigned char out2[256];
	unsigned char iv[32];

	memset(userKey,0,sizeof(userKey));
	memset(in,0x11,sizeof(in));
	memset(out,0x22,sizeof(out));
	memset(out2,0x33,sizeof(out2));

	hzSm4GenerateKey(&enKey,userKey,SM4_ENCRYPT);
	hzSm4GenerateKey(&deKey,userKey,SM4_DECRYPT);

//	HexDumpBuffer(stdout,(unsigned char*)&enKey,sizeof(sms4_key_t));
//	printf("---------->\n");
//	HexDumpBuffer(stdout,(unsigned char*)&deKey,sizeof(sms4_key_t));

	printf("------SM4 ECB\n");
	hzSm4EcbEncrypt(in,out,&enKey,SM4_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stdout,out,16);

	hzSm4EcbEncrypt(out,out2,&deKey,SM4_DECRYPT);
	printf("PlainText:\n");
	HexDumpBuffer(stdout,out2,16);

	printf("------SM4 CBC\n");
	memset(iv,0x11,sizeof(iv));
	hzSm4CbcEncrypt(in,16,out,&enKey,iv,SM4_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stdout,out,16);

	memset(iv,0x11,sizeof(iv));
	hzSm4CbcEncrypt(out,16,out2,&deKey,iv,SM4_DECRYPT);
	printf("PlainText:\n");
	HexDumpBuffer(stdout,out2,16);

	printf("------SM4 CFB\n");
	memset(iv,0x11,sizeof(iv));
	hzSm4CfbEncrypt(in,16,out,&enKey,iv,SM4_ENCRYPT);
	printf("CipherText:\n");
	HexDumpBuffer(stdout,out,16);

	memset(iv,0x11,sizeof(iv));
	hzSm4CfbEncrypt(out,16,out2,&enKey,iv,SM4_DECRYPT);
	printf("PlainText:\n");
	HexDumpBuffer(stdout,out2,16);

	printf("------SM4 CFB\n");
	memset(iv,0x11,sizeof(iv));
	hzSm4OfbEncrypt(in,16,out,&enKey,iv);
	printf("CipherText:\n");
	HexDumpBuffer(stdout,out,16);

	memset(iv,0x11,sizeof(iv));
	hzSm4OfbEncrypt(out,16,out2,&enKey,iv);
	printf("PlainText:\n");
	HexDumpBuffer(stdout,out2,16);


	return rc;
}

int sm2View(void)
{
	int rc = 0;

	printf("______SM2\n");
	EC_KEY *pukey,*prkey;

	pukey = EC_KEY_new();
	prkey = EC_KEY_new();
	rc = hzSm2GenerateKey(pukey,prkey);
//	printf("RC:%d\n",rc);
//	PEM_write_EC_PUBKEY(stdout,pukey);
//	PEM_write_ECPrivateKey(stdout,prkey,NULL,NULL,0,NULL,NULL);
//	EC_KEY_print_fp(stdout,prkey,0);
//	printf("\n------------\n");
//	EC_KEY_print_fp(stdout,pukey,0);

	unsigned char in[1024];
	unsigned char out[1024];
	unsigned char out2[1024];
	int inlen = 256;
	int outlen = 1024;
	int out2len = 1024;

	memset(in,0x11,inlen);
	rc = hzSm2Signle(NID_sm3,in,inlen,out,&outlen,prkey);
	printf("RC:%d LEN:%d\n",rc,outlen);
	rc = hzSm2Verify(NID_sm3,in,inlen,out,outlen,pukey);
	printf("RC:%d LEN:%d\n",rc,outlen);

	rc = hzSm2PublicKeyEncrypt(NID_sm3,in,inlen,out,&outlen,pukey);
	printf("RC:%d LEN:%d\n",rc,outlen);
	HexDumpBuffer(stdout,out,outlen);
	rc = hzSm2PrivateKeyDecrypt(NID_sm3,out,outlen,out2,&out2len,prkey);
	printf("RC:%d LEN:%d\n",rc,out2len);
	HexDumpBuffer(stdout,out2,out2len);

	EC_KEY_free(pukey);
	EC_KEY_free(prkey);
	return rc;
}

int sm9View(void)
{
	return 0;
}

int main(int argc, char **argv)
{
	printf("\n Hello OPENSSL.\n");

//Random
//	unsigned char buf[64];
//	printf("RC:%d\n",RANDOM(buf, 32));
//	HexDumpBuffer(stdout,buf,64);


//	//DES
//	desECB();
//	desCBC();
//	desCFB();
//	desOFB();
//
//	//AES
//	aes_encrypt();
//	aes_cbc_encrypt();
//	aes_cfb_encrypt();
//	aes_ofb_encrypt();
//
//	//RSA
//	rsaView();
//
//	//MD5
//	md5View();
//
//	//SM2
//	sm2View();
//
//	//SM3
//	sm3View();
//
//	//SM4
//	sm4View();

	//SM9
	sm9View();
	return 0;
}
