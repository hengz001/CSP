#include "mgrSvr.h"

int HANDLE = 0;

int gmnGenerateRandom(UCHAR *rnd, int len)
{
	return gmnGenerateRandomWng(rnd,len);
}

int GmnOpenSM2Card(void)
{
	return open("/dev/kstore0",O_RDWR);
}

int GmnOpenCard(void)
{
	return open("/dev/gmn_crypto",O_RDWR);
}


int GmnCloseCard(int handle)
{
	int rc;
	if(!handle){
		handle = HANDLE;
	}

	rc =  close(handle);
	return rc;
}
