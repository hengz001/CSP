/*
 * des.h
 *
 *  Created on: 2018Äê7ÔÂ10ÈÕ
 *      Author: MSI
 */

#ifndef INC_DES_H_
#define INC_DES_H_

#include <openssl/des.h>

int hzDesGenerateKey(unsigned char *key,int len);

//#ECB
int hzDesEcbEncryptSingle(unsigned char *key,unsigned char *in,unsigned char *out,int mode);

int hzDesEcbEncryptDouble(unsigned char *key,unsigned char *in,unsigned char *out,int mode);

int hzDesEcbEncryptTriple(unsigned char *key,unsigned char *in,unsigned char *out,int mode);

//#CBC
int hzDesCbcEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int hzDesCbcEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int hzDesCbcEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

//#CFB
int hzDesCfbEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int hzDesCfbEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int hzDesCfbEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

//#OFB
int hzDesOfbEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv);

int hzDesOfbEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv);

int hzDesOfbEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv);

#endif /* INC_DES_H_ */
