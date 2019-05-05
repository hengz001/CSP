/*
 * sm4.h
 *
 *  Created on: 2018��7��12��
 *      Author: MSI
 */

#ifndef SM4_H_
#define SM4_H_

#include <openssl/sms4.h>

#define SM4_ENCRYPT 1

#define SM4_DECRYPT 0


int hzSm4GenerateKey(sms4_key_t *key, unsigned char *userKey,int mode);

int hzSm4EcbEncrypt(const unsigned char *in, unsigned char *out,const sms4_key_t *key, int enc);

int hzSm4CbcEncrypt(const unsigned char *in, int len, unsigned char *out,const sms4_key_t *key,unsigned char *iv, int enc);

int hzSm4CfbEncrypt(const unsigned char *in, int len, unsigned char *out,const sms4_key_t *key,unsigned char *iv, int enc);

int hzSm4OfbEncrypt(const unsigned char *in, int len, unsigned char *out,const sms4_key_t *key,unsigned char *iv);

#endif /* SM2_H_ */
