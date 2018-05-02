#include "mgrSvr.h"

USHORT HsmGetIcGroup( void )
{
	return phsmShm->hsmcfg.rCs.ic_group;
}

USHORT HsmGetIcVersion( void )
{
	return phsmShm->hsmcfg.rCs.ic_version;
}

USHORT HsmGetIcIndex( void )
{
	return phsmShm->hsmcfg.rCs.ic_index;
}

USHORT HsmIcGetIndexFromGVI(UCHAR group, UCHAR version, UCHAR idx)
{
	UCHAR V, I;
	/* Reserved version 0 for special usage */
	V = HsmGetIcVersion() + 1;
	I = HsmGetIcIndex();
	// Check group, version, idx range here ...
	return ((group * V * I + version * I + idx)*LEN_KEY_RECORD);
}

int _readICindex(UCHAR group, UCHAR version, UCHAR idx, unsigned char *buffer, int len)
{
	int  rc;
	int  offset = LEN_CARDMEM - LEN_KEYSTORE + HsmIcGetIndexFromGVI(group, version, idx);
	rc = _read_lpsram(buffer, offset, len);
	return (rc < 0 ? 41 : 0);
}
