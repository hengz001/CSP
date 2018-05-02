#include "tcpSvr.h"


int error_return(int err_code, char *err, int *len)
{
	sprintf(err,"%02d",err_code);
	*len = 2;
	return err_code;
}
