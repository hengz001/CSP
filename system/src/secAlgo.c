#include "mgrSvr.h"

int DesRandomData(UCHAR *rnd, int len)
{
	return gmnGenerateRandom(rnd, len);
}
