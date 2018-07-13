/*
 * rsa.c
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */

#include "common.h"
#include "rsa.h"

struct rsa_st {
	int pad;
	long version;
	const RSA_METHOD *meth;
	ENGINE *engine;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;
	CRYPTO_EX_DATA ex_data;
	int references;
	int flags;
	BN_MONT_CTX *_method_mod_n;
	BN_MONT_CTX *_method_mod_p;
	BN_MONT_CTX *_method_mod_q;
	char *bignum_data;
	BN_BLINDING *blinding;
	BN_BLINDING *mt_blinding;
	CRYPTO_RWLOCK *lock;
};

//int _generateRsaKey(RSA *publicKey, RSA *privateKey)
//{
//	int rc = 0;
//	RSA *private_key , *public_key;
//	BIGNUM *bne;
//	unsigned char n[256];
//	unsigned char e[256];
//	unsigned char d[256];
//	unsigned char p[256];
//	unsigned char q[256];
//	unsigned char dmp1[256];
//	unsigned char dmq1[256];
//	unsigned char iqmp[256];
//	int nLen,eLen,dLen,pLen,qLen,dmp1Len,dmq1Len,iqmpLen;
//
//	private_key = RSA_new();
//	public_key = RSA_new();
//	bne = BN_new();
//
//	//
//	BN_set_word(bne,65537);
//	rc = RSA_generate_key_ex(private_key,1024,bne,NULL);
//	BN_clear_free(bne);
//
//	if(rc < 1)
//	{
//		goto out;
//	}
//
////	RSA_print_fp(stdout, private_key, 0);
////	PEM_write_RSAPrivateKey(stdout,private_key,NULL,NULL,NULL,NULL,NULL);
////	PEM_write_RSAPublicKey(stdout,private_key);
//	//
//
//	nLen = BN_bn2bin(private_key->n,n);
//	eLen = BN_bn2bin(private_key->e,e);
////	dLen = BN_bn2bin(private_key->d,d);
////	pLen = BN_bn2bin(private_key->p,p);
////	qLen = BN_bn2bin(private_key->q,q);
////	dmp1Len = BN_bn2bin(private_key->dmp1,dmp1);
////	dmq1Len = BN_bn2bin(private_key->dmq1,dmq1);
////	iqmpLen = BN_bn2bin(private_key->iqmp,iqmp);
//
////	printf("\n----------------------------->n %d\n",nLen);
////	HexDumpBuffer(stdout,n,nLen);
////	printf("\n----------------------------->e %d\n",eLen);
////	HexDumpBuffer(stdout,e,eLen);
////	printf("\n----------------------------->d %d\n",dLen);
////	HexDumpBuffer(stdout,d,dLen);
////	printf("\n----------------------------->p %d\n",pLen);
////	HexDumpBuffer(stdout,p,pLen);
////	printf("\n----------------------------->q %d\n",qLen);
////	HexDumpBuffer(stdout,q,qLen);
////	printf("\n----------------------------->dmp1 %d\n",dmp1Len);
////	HexDumpBuffer(stdout,dmp1,dmp1Len);
////	printf("\n----------------------------->dmq1 %d\n",dmq1Len);
////	HexDumpBuffer(stdout,dmq1,dmq1Len);
////	printf("\n----------------------------->iqmp %d\n",iqmpLen);
////	HexDumpBuffer(stdout,iqmp,iqmpLen);
//
//	public_key->n = BN_bin2bn(n,nLen,NULL);
//	public_key->e = BN_bin2bn(e,eLen,NULL);
////	PEM_write_RSAPublicKey(stdout,public_key);
//
////	printf("CHECK:%d\n",RSA_check_key(private_key));
//	char from[] = "zhuheng";
//	unsigned char to[256];
//	unsigned char data[256];
//	int len;
//	int rLen = 0;
//
//	len = sizeof(from);
//	printf("PlainText:\n");
//	HexDumpBuffer(stdout,from,len);
//	rc = RSA_public_encrypt(len,from,to,public_key,RSA_PKCS1_PADDING);
//	printf("RC:%d\n",rc);
//	printf("CipherText:\n");
//	HexDumpBuffer(stdout,to,rc);
//
//	rc = RSA_private_decrypt(rc,to,data,private_key,RSA_PKCS1_PADDING);
//	printf("RC:%d\n",rc);
//	printf("PlainText:\n");
//	HexDumpBuffer(stdout,data,rc);
//
//	rc = RSA_private_encrypt(len,from,data,private_key,RSA_PKCS1_PADDING);
//	printf("RC:%d\n",rc);
//	printf("CipherText:\n");
//	HexDumpBuffer(stdout,data,rc);
//
//	rc = RSA_public_decrypt(rc,data,to,public_key,RSA_PKCS1_PADDING);
//	printf("RC:%d\n",rc);
//	printf("PlainText:\n");
//	HexDumpBuffer(stdout,to,rc);
//
//	rc = RSA_sign(NID_md5,from,len,to,&rLen,private_key);
//	printf("RC:%d\n",rc);
//	printf("Sign:\n");
//	HexDumpBuffer(stdout,to,rLen);
//
//	rc = RSA_verify(NID_md5,from,len,to,rLen,public_key);
//	printf("RC:%d\n",rc);
//	printf("Verify:\n");
//
//out:
//	RSA_free(public_key);
//	RSA_free(private_key);
//	return rc;
//}

int hzRsaGenerateKey(int bits, int e_Dec, RSA *publicKey, RSA *privateKey)
{
	int rc = 0;
	BIGNUM *bne;
	int nLen, eLen;
	unsigned char *n;
	unsigned char *e;

	bne = BN_new();
	BN_set_word(bne, e_Dec);
	rc = RSA_generate_key_ex(privateKey, bits, bne, NULL);
	BN_clear_free(bne);

	if (rc < 1) {
		return rc;
	}

	rc = RSA_size(privateKey);
	n = (unsigned char*) malloc(sizeof(unsigned char) * rc);
	e = (unsigned char*) malloc(sizeof(unsigned char) * rc);
	nLen = BN_bn2bin(privateKey->n, n);
	eLen = BN_bn2bin(privateKey->e, e);
	publicKey->n = BN_bin2bn(n, nLen, NULL);
	publicKey->e = BN_bin2bn(e, eLen, NULL);
	free(n);
	free(e);
	return RSA_check_key(privateKey);
}

int hzRsaSign(int hashType, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *prKey)
{
	return RSA_sign(hashType, m, m_length, sigret, siglen, prKey);
}

int hzRsaVerify(int hshType, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, RSA *puKey)
{
	return RSA_verify(hshType, m, m_length, sigbuf, siglen, puKey);
}

int hzRsaPublicKeyEncrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return RSA_public_encrypt(flen,from,to,rsa,padding);
}
int hzRsaPublicKeyDecrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return RSA_public_decrypt(flen,from,to,rsa,padding);
}

int hzRsaPrivateKeyEncrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return RSA_private_encrypt(flen,from,to,rsa,padding);
}

int hzRsaPrivateKeyDecrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return RSA_private_decrypt(flen,from,to,rsa,padding);
}

