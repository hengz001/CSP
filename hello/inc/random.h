/*
 * random.h
 *
 *  Created on: 2018��7��12��
 *      Author: MSI
 */

#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <openssl/rand.h>

int hzRandom(unsigned char *buf, int num);

#endif
