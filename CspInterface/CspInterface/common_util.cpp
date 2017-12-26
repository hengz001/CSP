#include "stdafx.h"

unsigned char *short2hex(unsigned short s, unsigned char *p){
	*p++ = (s>>8)&0xff;
	*p++ = s & 0xff;
	return p;
}

unsigned short hex2short(unsigned char *p){
	unsigned short s;
	s = *p++;
	s = (s << 8) | *p++;
	return s;
}