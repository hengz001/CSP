#ifndef COMMON_UTIL_H
#define COMMON_UTUL_H

unsigned char *short2hex(unsigned short s, unsigned char *p);

unsigned short hex2short(unsigned char *p);

unsigned long filelength(char *fname);

char *GetTime(char *Buffer, int Len, const char *format);
#endif