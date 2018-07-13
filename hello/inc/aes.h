/*
 * aes.h
 *
 *  Created on: 2018Äê7ÔÂ11ÈÕ
 *      Author: MSI
 */
#ifndef __AES_Z__
#define __AES_Z__
#include <openssl/aes.h>


int hzAesGenerateKey(unsigned char *userKey, int bits, AES_KEY *key, int mode);

int hzAesEncrypt(unsigned char *in, unsigned char *out, AES_KEY *key, int mode);

int hzAesCbcEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv, int mode);

int hzAesCfbEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv, int mode);

int hzAesOfbEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv);

#endif
