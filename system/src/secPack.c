#include "mgrSvr.h"

void RevULData(U16 *buff, int buff_len)
{
	int i;
	U16 n;
	for(i=0; i<buff_len; i++)
	{
		n = buff[i];
		buff[i] = (n & 0x00ff)<<8 | (n & 0xff00)>>8 ;
	}
}
