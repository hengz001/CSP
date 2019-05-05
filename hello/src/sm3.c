/*
 * sm3.c
 *
 *  Created on: 2018��7��12��
 *      Author: MSI
 */

#include "common.h"
#include "sm3.h"

int hzSM3(unsigned char *from, int flen, unsigned char *to)
{
	sm3_ctx_t c;
	sm3_init(&c);
	sm3_update(&c,from,flen);
	sm3_final(&c,to);
	return 0;
}
