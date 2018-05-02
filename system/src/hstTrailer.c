#include "tcpSvr.h"

char *FindMessageTrailer(unsigned char *Buf, int len, unsigned char ch, int charset)
{
	register int i;
	UCHAR *p = Buf+len,*pAscii;

	for(i=len; i>=0 ; i--,p--)
	{
		if(*p==ch){
			int tLen = len - (p+1 - Buf);
			if(tLen)
			{
				if(charset == CHARSET_EBCDIC){
					pAscii = (UCHAR *)malloc(tLen+1);
					EbcdicToAscii(p+1,pAscii,tLen);
				}else if(charset == CHARSET_IBM1388){
					pAscii = (UCHAR *)malloc(tLen+1);
					IBM1388Decode(p+1,pAscii,&tLen);
				}else{
					pAscii = p+1;
				}

				if(isBufferPrint((char*)pAscii,tLen))
				{
					if(charset!=CHARSET_ASCII)
					{
						free(pAscii);
					}
					return (char*)p;
				}
			}
		}
	}
	return NULL;
}
