/*
 * random.c
 *
 *  Created on: 2018Äê7ÔÂ12ÈÕ
 *      Author: MSI
 */


#include "common.h"
#include "random.h"


int hzRandom(unsigned char *buf, int num)
{
	return RAND_bytes(buf,num);
}

