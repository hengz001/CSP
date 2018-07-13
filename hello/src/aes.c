/*
 * aes.c
 *
 *  Created on: 2018Äê7ÔÂ11ÈÕ
 *      Author: MSI
 */

#include "common.h"
#include "aes.h"


int hzAesGenerateKey(unsigned char *userKey, int bits, AES_KEY *key, int mode)
{
	int rc = 0;

	switch(mode)
	{
	case AES_ENCRYPT:
		rc = AES_set_encrypt_key(userKey,bits,key);
		break;
	case AES_DECRYPT:
		rc = AES_set_decrypt_key(userKey,bits,key);
		break;
	default:
		rc = -1;
		break;
	}
	return rc;
}

int hzAesEncrypt(unsigned char *in, unsigned char *out, AES_KEY *key, int mode)
{
	int rc = 0;

	switch(mode)
	{
	case AES_ENCRYPT:
		AES_encrypt(in,out,key);
		break;
	case AES_DECRYPT:
		AES_decrypt(in,out,key);
		break;
	default:
		rc = -1;
		break;
	}
	return rc;
}

int hzAesCbcEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv, int mode)
{
	AES_cbc_encrypt(in,out,len,key,iv,mode);
	return 0;
}

int hzAesCfbEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv, int mode)
{
	int num = 0;

	AES_cfb128_encrypt(in,out,len,key,iv,&num,mode);
	return 0;
}

int hzAesOfbEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv)
{
	int num = 0;

	AES_ofb128_encrypt(in,out,len,key,iv,&num);
	return 0;
}
