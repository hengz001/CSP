#include "stdafx.h"

static char IP[64];
static int PORT;
static char CHECKVALUE[64];

void setHsmIP(char * ip) {
	memcpy(IP,ip,strlen(ip));
}

char * getHsmIP() {
	return IP;
}

void setHsmPORT(int port) {
	PORT = port;
}

int getHsmPORT() {
	return PORT;
}

void setHsmCV(char * checkValue) {
	memcpy(CHECKVALUE,checkValue,strlen(checkValue));
}

char * getHsmCV() {
	return CHECKVALUE;
}

unsigned long filelength(char *fname)
{
	HFILE	handle;
	long start, end;

	/*** open the file to calculate the length ***/
	handle = _lopen(fname, OF_READ/*O_RDONLY*/);
	start = _llseek(handle, 0L, SEEK_SET);
	end = _llseek(handle, 0L, SEEK_END);

	/*** close the file ***/
	_lclose(handle);
	return(end - start);
}

char *GetTime(char *Buffer, int Len, const char *format)
{
	time_t clock;

	clock = time((time_t *)0);
	strftime(Buffer, Len, format, localtime(&clock));
	return (Buffer);
}