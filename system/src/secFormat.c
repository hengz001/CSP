#include "mgrSvr.h"

char *StripOffWhiteSpaces(char *buffer,int len)
{
	char *tmp_str;
	register unsigned char *p1,*p2;

	tmp_str = (char *)malloc(sizeof(char)*len);

	memset(tmp_str,0,len);

	for(p1=(unsigned char *)buffer,p2=(unsigned char *)tmp_str;*p1;p1++)
	{
		if(!isspace(*p1)&&(*p1!='\n'))
		{
			*p2++=*p1;
		}
	}

	memcpy(buffer, tmp_str, (char *)p2-tmp_str);
	buffer[(char *)p2-tmp_str] = 0;

	/*** clear the temp storage ***/
	DesMemClean(tmp_str,len);
	//memset(tmp_str,0,len);

	free(tmp_str);

	return(buffer);
}
