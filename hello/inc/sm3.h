/*
 * sm3.h
 *
 *  Created on: 2018��7��12��
 *      Author: MSI
 */

#ifndef SM3_H_
#define SM3_H_

#include <openssl/sm3.h>

int hzSM3(unsigned char *from, int flen, unsigned char *to);

#endif /* SM2_H_ */
