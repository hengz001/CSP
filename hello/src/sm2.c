/*
 * sm2.c
 *
 *  Created on: 2018年7月12日
 *      Author: MSI
 */

#include "common.h"
#include "sm2.h"

struct ec_key_st {
    const EC_KEY_METHOD *meth;
    ENGINE *engine;
    int version;
    EC_GROUP *group; //密钥参数
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    unsigned int enc_flag;
    point_conversion_form_t conv_form;
    int references;
    int flags;
    CRYPTO_EX_DATA ex_data;
    CRYPTO_RWLOCK *lock;
};

struct ec_point_st {
    const EC_METHOD *meth;
    /*
     * All members except 'meth' are handled by the method functions, even if
     * they appear generic
     */
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;                  /* Jacobian projective coordinates: * (X, Y,
                                 * Z) represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
};


int hzSm2GenerateKey(EC_KEY* pukey, EC_KEY* prkey)
{
	int rc;
	EC_GROUP *group = NULL;
	group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("sm2p256v1"));
	if(group == NULL)
	{
		rc =  -1;
	}
	else
	{
		rc = EC_KEY_set_group(prkey,group);
		rc = EC_KEY_set_group(pukey,group);
		rc = EC_KEY_generate_key(prkey);
		if(rc < 0)
		{
			rc =  -2;
		}
		else
		{
			rc = EC_KEY_set_public_key(pukey,prkey->pub_key);
		}

	}

	EC_GROUP_free(group);
	return rc;
}

int hzSm2PublicKeyEncrypt(int type, const unsigned char *in, size_t inlen,unsigned char *out, int *outlen, EC_KEY *ec_key)
{
	return SM2_encrypt(type,in,inlen,out, (size_t *)outlen,ec_key);
}

int hzSm2PrivateKeyDecrypt(int type, const unsigned char *in, size_t inlen,unsigned char *out, int *outlen, EC_KEY *ec_key)
{
	return SM2_decrypt( type,in,inlen,out, (size_t *)outlen, ec_key);
}

int hzSm2Signle(int type, const unsigned char *dgst, int dgstlen,unsigned char *sig,  int *siglen, EC_KEY *eckey)
{
	return SM2_sign(type,dgst,dgstlen,sig,(unsigned int*)siglen,eckey);
}

int hzSm2Verify(int type, const unsigned char *dgst, int dgstlen,const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
	return SM2_verify(type,dgst,dgstlen,sig, siglen, ec_key);
}

//int generateSm2Key()
//{
//	int rc = 0;
//	EC_KEY *key;
//	EC_KEY *puKey, *prKey;
//	EC_GROUP *group = NULL;
//	unsigned char puBuf[1024];
//	unsigned char prBuf[1024];
//	int pulen;
//	int prlen;
//	BIGNUM *bn;
//	group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("sm2p256v1"));
//
//	if(NULL == group)
//	{
//		rc = -1;
//		goto out;
//	}
//
//	key = EC_KEY_new();
//	if(EC_KEY_set_group(key,group)==0)
//	{
//		rc = -2;
//		goto out;
//	}
//
//	rc = EC_KEY_generate_key(key);
//
//	bn = EC_POINT_point2bn(group,key->pub_key,POINT_CONVERSION_UNCOMPRESSED,NULL,NULL);
//	pulen = BN_bn2bin(bn,puBuf);
//	printf("PUBLIC SIZE:%d\n",pulen);
//	HexDumpBuffer(stdout,puBuf,pulen);
//
//	prlen = BN_bn2bin(key->priv_key,prBuf);
//	printf("PRIVATE SIZE:%d\n",prlen);
//	HexDumpBuffer(stdout,prBuf,prlen);
//
//
//
//	unsigned char dgst[] = "zhuheng";
//	int dgstLen = sizeof(dgst);
//	unsigned char sign[1024];
//	int sigLen = sizeof(sign);
//	unsigned char out[1024];
//	int outLen = sizeof(out);
//
//
//	prKey = EC_KEY_new();
//	puKey = EC_KEY_new();
//	EC_KEY_set_group(prKey,group);
//	EC_KEY_set_group(puKey,group);
//
//	rc = EC_KEY_set_private_key(prKey,BN_bin2bn(prBuf,prlen,NULL));
//	printf("Set private key. RC:%d\n",rc);
//	rc = EC_KEY_set_public_key(puKey,EC_POINT_bn2point(group,(BN_bin2bn(puBuf,pulen,NULL)),NULL,NULL));
//	printf("Set public key. RC:%d\n",rc);
//
//	rc = SM2_sign(NID_sm3,dgst,dgstLen,sign,&sigLen,prKey);
//	printf("RC:%d\n",rc);
//	HexDumpBuffer(stdout,sign,sigLen);
//
//	rc = SM2_verify(NID_sm3,dgst,dgstLen,sign,sigLen,puKey);
//	printf("RC:%d\n",rc);
//
//	rc = SM2_encrypt(NID_sm3,dgst,dgstLen,sign,&sigLen,puKey);
//	printf("RC:%d\n",rc);
//	HexDumpBuffer(stdout,sign,sigLen);
//
//	rc = SM2_decrypt(NID_sm3,sign,sigLen,out,&outLen,prKey);
//	printf("RC:%d\n",rc);
//	HexDumpBuffer(stdout,out,outLen);
//
//out:
//	EC_GROUP_free(group);
//	EC_KEY_free(key);
//	EC_KEY_free(prKey);
//	EC_KEY_free(puKey);
//	return rc;
//}
