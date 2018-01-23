#ifndef COMMON_UTIL_H
#define COMMON_UTUL_H


void setHsmIP(char * ip);

char * getHsmIP();

void setHsmPORT(int port);

int getHsmPORT();

void setHsmCV(char * checkValue);

char * getHsmCV();

unsigned long filelength(char *fname);

char *GetTime(char *Buffer, int Len, const char *format);
#endif