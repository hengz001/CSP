/*
 * sm2.h
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */

#ifndef SM2_H_
#define SM2_H_

#include <openssl/sm2.h>

int hzSm2GenerateKey(EC_KEY* pukey, EC_KEY* prkey);

int hzSm2PublicKeyEncrypt(int type, const unsigned char *in, size_t inlen,unsigned char *out, int *outlen, EC_KEY *ec_key);

int hzSm2PrivateKeyDecrypt(int type, const unsigned char *in, size_t inlen,unsigned char *out, int *outlen, EC_KEY *ec_key);

int hzSm2Signle(int type, const unsigned char *dgst, int dgstlen,unsigned char *sig,  int *siglen, EC_KEY *eckey);

int hzSm2Verify(int type, const unsigned char *dgst, int dgstlen,const unsigned char *sig, int siglen, EC_KEY *ec_key);

#endif /* SM2_H_ */
