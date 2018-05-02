#include "mgrSvr.h"

int ClearPort(int hsmdev)
{

	if(HsmGetPrinterPort() == PRINT_SERIAL)
	{
		return tcflush(hsmdev,TCIOFLUSH);
	}else if(HsmGetPrinterPort() == PRINT_PARALLEL){
		int status;
		return ioctl(hsmdev,LPRESET,(char*)&status);
	}
	return 0;
}
