#include "mgrSvr.h"

int DesRandomData(UCHAR *rnd, int len)
{
	return gmnGenerateRandom(rnd, len);
}

void *DesMemClean(void *buffer, int len)
{
	/**** 2525 codes ****/
	//memset(buffer,0x55,len);
	/**** 5252 codes ****/
	//memset(buffer,0xAA,len);
	/**** all one's codes ****/
	//memset(buffer,0x77,len);
	/**** all zero's codes ****/
	return (void *)memset(buffer,0x00,len);
}
