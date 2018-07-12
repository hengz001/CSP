/*
 * aes.h
 *
 *  Created on: 2018Äê7ÔÂ11ÈÕ
 *      Author: MSI
 */
#ifndef __AES_Z__
#define __AES_Z__
#include <openssl/aes.h>


int generateAesKey(unsigned char *userKey, int bits, AES_KEY *key, int mode);

int aesEncrypt(unsigned char *in, unsigned char *out, AES_KEY *key, int mode);

int aesCbcEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv, int mode);

int aesCfbEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv, int mode);

int aesOfbEncrypt(unsigned char *in, unsigned char *out,int len, AES_KEY *key, unsigned char *iv);








#endif
