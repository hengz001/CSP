/*
 * md5.h
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */

#ifndef __MD5_H__
#define __MD5_H__
#include <openssl/md5.h>

int hzMD5(unsigned char *from, int flen, unsigned char *to);

#endif
