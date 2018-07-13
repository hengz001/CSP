/*
 * md5.c
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */

#include "common.h"
#include "md5.h"

int hzMD5(unsigned char *from, int flen, unsigned char *to)
{
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c,from,flen);
	return MD5_Final(to,&c);
}
