

USHORT HsmGetIcGroup( void );

USHORT HsmGetIcVersion( void );

USHORT HsmGetIcIndex( void );

int _readICindex(UCHAR group, UCHAR version, UCHAR idx, unsigned char *buffer, int len);

USHORT HsmIcGetIndexFromGVI(UCHAR group, UCHAR version, UCHAR idx);
