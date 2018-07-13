/*
 * rsa.h
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */


#ifndef __RSA_H__
#define __RSA_H__

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int hzRsaGenerateKey(int bits, int e_Dec, RSA *publicKey, RSA *privateKey);

int hzRsaSign(int hashType, const unsigned char *m, unsigned int m_length,unsigned char *sigret, unsigned int *siglen, RSA *prKey);

int hzRsaVerify(int hshType, const unsigned char *m, unsigned int m_length,const unsigned char *sigbuf, unsigned int siglen, RSA *puKey);

int hzRsaPublicKeyEncrypt(int flen, const unsigned char *from, unsigned char *to,RSA *rsa, int padding);

int hzRsaPublicKeyDecrypt(int flen, const unsigned char *from, unsigned char *to,RSA *rsa, int padding);

int hzRsaPrivateKeyEncrypt(int flen, const unsigned char *from, unsigned char *to,RSA *rsa, int padding);

int hzRsaPrivateKeyDecrypt(int flen, const unsigned char *from, unsigned char *to,RSA *rsa, int padding);
#endif
