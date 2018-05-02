
char *strupper(char *str);

int HsmCheckIpSyntax(char *ip);

ULONG dot2local(char *cp);

char *local2dot(ULONG ip);

int get_hw_address(ULONG name, UCHAR *hw);

int hw2local(char *hw, UCHAR *pk);

int PackBCD(char *InBuf, UCHAR *OutBuf, int len);

int UnpackBCD(UCHAR *InBuf, UCHAR *OutBuf, int Len);

USHORT hex2short(UCHAR *p);

UCHAR *short2hex(USHORT s, UCHAR *p);

int isBufferPrint(char *buffer, int len);

int HexDumpBuffer(FILE *fp,UCHAR *buffer, int length);

int isBufferDec(char *buffer,int len);
