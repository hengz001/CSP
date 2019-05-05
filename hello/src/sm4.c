/*
 * sm4.c
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */

#include "common.h"
#include "sm4.h"


int hzSm4GenerateKey(sms4_key_t *key, unsigned char *userKey,int mode)
{
	int rc = 0;

	switch (mode) {
		case SM4_ENCRYPT:
			sms4_set_encrypt_key(key,userKey);
			break;
		case SM4_DECRYPT:
			sms4_set_decrypt_key(key,userKey);
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

int hzSm4EcbEncrypt(const unsigned char *in, unsigned char *out,const sms4_key_t *key, int enc)
{
	sms4_ecb_encrypt(in,out,key,enc);
	return 0;
}

int hzSm4CbcEncrypt(const unsigned char *in, int len, unsigned char *out,const sms4_key_t *key,unsigned char *iv, int enc)
{
	sms4_cbc_encrypt(in,out,len,key,iv,enc);
	return 0;
}


int hzSm4CfbEncrypt(const unsigned char *in, int len, unsigned char *out,const sms4_key_t *key,unsigned char *iv, int enc)
{
	int num = 0;

	sms4_cfb128_encrypt(in,out,len,key,iv,&num,enc);
	return 0;
}

int hzSm4OfbEncrypt(const unsigned char *in, int len, unsigned char *out,const sms4_key_t *key,unsigned char *iv)
{
	int num = 0;

	sms4_ofb128_encrypt(in,out,len,key,iv,&num);
	return 0;
}









