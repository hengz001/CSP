#include "mgrSvr.h"
#include "tcpSvr.h"

int isBufferAllTheSameChar(char *Buf, char ch,int len)
{
	register int i;
	int rc = 1;

	for(i=0; i<len; i++){
		rc = rc && (Buf[i] == ch);
	}
	return (rc);
}

int CheckKeysParity(unsigned char *key)
{
	int   i;

	for(i=1;i<MAX_LMKS;i++)
	{
		if(!desCheckKeyOddParity(key+i*LEN_LMK,LEN_LMK))
			return 0;
	}
	return (i==MAX_LMKS);
}

int CheckOldLMKsParity(void)
{
	return CheckKeysParity(phsmShm->oldLMKs[0]);
}

int CheckLMKsParity(void)
{
	return CheckKeysParity(phsmShm->LMKs[0]);
}
