/*
 * md5.h
 *
 *  Created on: 2018��7��12��
 *      Author: MSI
 */

#ifndef __MD5_H__
#define __MD5_H__
#include <openssl/md5.h>

int hzMD5(unsigned char *from, int flen, unsigned char *to);

#endif
