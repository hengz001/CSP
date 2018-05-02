#include "mgrSvr.h"

int __read_nvram(int offset, UCHAR *buffer, int len)
{
	int dev_kstoreNVRAM;
	int rd_len = -1;

	dev_kstoreNVRAM = open("/dev/kstore1",O_RDONLY);

	if(dev_kstoreNVRAM == -1)
	{
		return -1;
	}
	lseek(dev_kstoreNVRAM, offset, SEEK_SET);

	rd_len = read(dev_kstoreNVRAM, buffer, len);
	if(rd_len != len)
	{
		close(dev_kstoreNVRAM);
		return (-2);
	}

	close(dev_kstoreNVRAM);

	return 0;
}

int __write_nvram(int offset, UCHAR *buffer, int len)
{
	int dev_kstoreNVRAM;
	int wrt_len = -1;

	dev_kstoreNVRAM = open("/dev/kstore1",O_RDWR);
	if(dev_kstoreNVRAM == -1)
	{
		return (-1);
	}
	lseek(dev_kstoreNVRAM,offset,SEEK_SET);

	wrt_len = write(dev_kstoreNVRAM,buffer,len);
	if(wrt_len != len)
	{
		close(dev_kstoreNVRAM);
		return (-2);
	}

	close(dev_kstoreNVRAM);
	return 0;
}

int _read_nvram(UCHAR *buffer, int len)
{
	return __read_nvram(0,buffer,len);
}

int _write_nvram(unsigned char *buffer, int len)
{
	return __write_nvram(0, buffer, len);
}
