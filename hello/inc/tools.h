#ifndef _TOOLS_
#define _TOOLS_


int HexDumpOneLine(FILE *fp, unsigned char *buffer, int *len, int *line);

int HexDumpBuffer(FILE *fp, unsigned char *buffer, int length);

int PackBCD(char *inBuf, unsigned char *outBuf, int len);

int UnPackBCD(unsigned char *inBuf, char *outBuf, int len);


#endif
