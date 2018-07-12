/*
 * des.h
 *
 *  Created on: 2018Äê7ÔÂ10ÈÕ
 *      Author: MSI
 */

#ifndef INC_DES_H_
#define INC_DES_H_

#include <openssl/des.h>

int generateDesKey(unsigned char *key,int len);

//#ECB
int desEcbEncryptSingle(unsigned char *key,unsigned char *in,unsigned char *out,int mode);

int desEcbEncryptDouble(unsigned char *key,unsigned char *in,unsigned char *out,int mode);

int desEcbEncryptTriple(unsigned char *key,unsigned char *in,unsigned char *out,int mode);

//#CBC
int desCbcEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int desCbcEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int desCbcEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

//#CFB
int desCfbEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int desCfbEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

int desCfbEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv,int mode);

//#OFB
int desOfbEncryptSingle(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv);

int desOfbEncryptDouble(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv);

int desOfbEncryptTriple(unsigned char *key,unsigned char *in, int iLen, unsigned char *out,unsigned char *iv);

#endif /* INC_DES_H_ */
