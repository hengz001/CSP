#include "mgrSvr.h"

int _read_lpsram(UCHAR *buffer, int offset, int len)
{
	int dev_kstoreLPSRAM;
	int pos = -1;
	int rd_len = -1;

	dev_kstoreLPSRAM = open("/dev/kstore0",O_RDONLY);
	if(dev_kstoreLPSRAM == -1)
	{
		return (-1);
	}

	pos = lseek(dev_kstoreLPSRAM,offset,SEEK_SET);
	if(pos >= (LPSRAM_SIZE-1)){
		close(dev_kstoreLPSRAM);
		return (-2);
	}

	rd_len = read(dev_kstoreLPSRAM,buffer, len);
	if(rd_len != len){
		close(dev_kstoreLPSRAM);
		return -3;
	}

	close(dev_kstoreLPSRAM);
	return 0;
}

int gmnGenerateRandomWng(UCHAR *rnd, int len)
{
	int rc = 0,*p;
	int handle = -1;

	handle = open("/dev/kstore0",O_RDONLY);
	if(handle == -1){
		return -1;
	}

	p = (int*)rnd;
	*p = len;

	rc = ioctl(handle, CARD_RANDOM, p);

	if(rc != 0){
		close(handle);
		return -1;
	}
	close(handle);

	RevULData((U16 *)p,len/2);
	return rc;
}



