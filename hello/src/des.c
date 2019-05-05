/*
 * des.c
 *
 *  Created on: 2018Äê7ÔÂ10ÈÕ
 *      Author: MSI
 */

#include "common.h"
#include "des.h"

int hzDesGenerateKey(unsigned char *key,int len)
{
	int i;
	int rc = 0;

	for(i=0; i<len;i+=8)
	{
		rc = DES_random_key((DES_cblock *)(key+i));
	}
	return rc;
}

int hzDesEcbEncryptSingle(unsigned char *key,unsigned char *in,unsigned char *out,int mode)
{
	int rc = 0;
	DES_key_schedule schedule;

	DES_set_key_unchecked((DES_cblock *)key,&schedule);
	DES_ecb_encrypt((DES_cblock *)in,(DES_cblock *)out,&schedule,mode);
	return rc;
}

int hzDesEcbEncryptDouble(unsigned char *key,unsigned char *in,unsigned char *out,int mode)
{
	int rc = 0;
	DES_key_schedule schedule1,schedule2;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_ecb2_encrypt((DES_cblock *)in,(DES_cblock *)out,&schedule1,&schedule2,mode);
	return rc;
}

int hzDesEcbEncryptTriple(unsigned char *key,unsigned char *in,unsigned char *out,int mode)
{
	int rc = 0;
	DES_key_schedule schedule1,schedule2,schedule3;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_set_key_unchecked((DES_cblock *)(key+16),&schedule3);
	DES_ecb3_encrypt((DES_cblock *)in,(DES_cblock *)out,&schedule1,&schedule2,&schedule3,mode);
	return rc;
}

int hzDesCbcEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode)
{
	int rc = 0;
	DES_key_schedule schedule;

	DES_set_key_unchecked((DES_cblock *)key,&schedule);
	DES_cbc_encrypt(in,out,iLen,&schedule,(DES_cblock *)iv,mode);
	return rc;
}

int hzDesCbcEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode)
{
	int rc = 0;
	DES_key_schedule schedule1,schedule2;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);

	DES_ede3_cbc_encrypt(in,out,iLen,&schedule1,&schedule2,&schedule1,(DES_cblock *)iv,mode);

	return rc;
}

int hzDesCbcEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode)
{
	int rc = 0;
	DES_key_schedule schedule1,schedule2,schedule3;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_set_key_unchecked((DES_cblock *)(key+8+8),&schedule3);

	DES_ede3_cbc_encrypt(in,out,iLen,&schedule1,&schedule2,&schedule3,(DES_cblock *)iv,mode);
	return rc;
}

int hzDesCfbEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode)
{
	int rc = 0;
	int num = 0;
	DES_key_schedule schedule;

	DES_set_key_unchecked((DES_cblock *)key,&schedule);
	DES_cfb64_encrypt(in,out,iLen,&schedule,(DES_cblock *)iv,&num,mode);
	return rc;
}

int hzDesCfbEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode)
{
	int rc = 0;
	int num = 0;
	DES_key_schedule schedule1,schedule2;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_ede3_cfb64_encrypt(in,out,iLen,&schedule1,&schedule2,&schedule1,(DES_cblock *)iv,&num,mode);
	return rc;
}

int hzDesCfbEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode)
{
	int rc = 0;
	int num = 0;
	DES_key_schedule schedule1,schedule2,schedule3;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_set_key_unchecked((DES_cblock *)(key+8+8),&schedule3);
	DES_ede3_cfb64_encrypt(in,out,iLen,&schedule1,&schedule3,&schedule1,(DES_cblock *)iv,&num,mode);
	return rc;
}

//
int hzDesOfbEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv)
{
	int rc = 0;
	int num = 0;
	DES_key_schedule schedule;

	DES_set_key_unchecked((DES_cblock *)key,&schedule);
	DES_ofb64_encrypt(in,out,iLen,&schedule,(DES_cblock *)iv,&num);
	return rc;
}

int hzDesOfbEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv)
{
	int rc = 0;
	int num = 0;
	DES_key_schedule schedule1,schedule2;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_ede3_ofb64_encrypt(in,out,iLen,&schedule1,&schedule2,&schedule1,(DES_cblock *)iv,&num);
	return rc;
}

int hzDesOfbEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv)
{
	int rc = 0;
	int num = 0;
	DES_key_schedule schedule1,schedule2,schedule3;

	DES_set_key_unchecked((DES_cblock *)key,&schedule1);
	DES_set_key_unchecked((DES_cblock *)(key+8),&schedule2);
	DES_set_key_unchecked((DES_cblock *)(key+8+8),&schedule3);
	DES_ede3_ofb64_encrypt(in,out,iLen,&schedule1,&schedule3,&schedule1,(DES_cblock *)iv,&num);
	return rc;
}

