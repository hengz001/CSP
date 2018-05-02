#include "mgrSvr.h"

#define _PATH_PROCNET_ARP	 "/proc/net/arp"

#define LINE_LEN 16

char *strupper(char *str)
{
	char *p = str;
	for(;*p;*p=toupper(*p),p++);
	return str;
}

int CheckIpSyntax(char *buf)
{
	char *p = buf;
	int i,count=0;
	int rc=0;
	if(strlen(p)>15){
		return (-1);
	}
	for(i=0;i<16;i++)
	{
		if(*p++ == '.') ++count;
	}
	if(count!=3) return (-2);
	p = buf;
	while(*p){
		if(!isdigit(*p)&&(*p!='.')){
			rc++;
		}
		p++;
	}
	return rc;
}

int isBufferDec(char *buffer,int len)
{
	int i;
	for(i=0;(i<len)&&isdigit((int)buffer[i]);i++);
	return (i==len);
}

int HsmCheckIpSyntax(char *ip)
{
	char addr[16+1],*p,*q;
	int rc = 1,i;
	if(CheckIpSyntax(ip)){
		return -1*rc;
	}
	rc++;
	if(strlen(ip)>15){
		return -1*rc;
	}
	strcpy(addr,ip);
	*(addr+strlen(addr))='.';
	p = addr;
	for(i=0;i<4;i++){
		q = strchr(p,'.');
		*q = 0;
		rc++;
		if(!isBufferDec(p,strlen(p))){
			return -1*rc;
		}
		rc++;
		if(atoi(p)>255){
			return -1*rc;
		}
		p=q+1;
	}
	return 0;
}

ULONG dot2local(char *cp)
{
	struct in_addr inp;
	if((inet_aton(cp,&inp)) != 0){
		return (inp.s_addr);
	}
	return (0L);
}

char *local2dot(ULONG ip)
{
	struct in_addr inp;
	inp.s_addr = ip;
	return inet_ntoa(inp);
}

int get_hw_address(ULONG name, UCHAR *hw)
{
	char host[100];
	char line[200];
	FILE *fp;
	int num;
	char ip[100], hwa[100], mask[100], dev[100];
	int type,flags;
	int entries = 0,showed = 0;

	host[0] = '\0';

	strcpy(host,local2dot(name));

	if((fp=fopen(_PATH_PROCNET_ARP,"r")) == NULL){
		return 0;
	}

	if(fgets(line,sizeof(line),fp)!=NULL){
		for(;fgets(line,sizeof(line),fp);){
			num = sscanf(line,"%s 0x%x 0x%x %100s %100s %100s\n",
					ip,&type,&flags,hwa,mask,dev);
			if(num<4){
				break;
			}
			entries++;
			if(host[0] && strcmp(ip,host)){
				continue;
			}
			showed++;
			break;
		}
	}
	fclose(fp);
	if(host[0] && !showed){
		return 0;
	}
	hw2local(hwa,hw);
	return 1;
}

int hw2local(char *hw, UCHAR *pk)
{
	char local[2*6+1];
	char *p = hw,*q = local;
	int i;

	for(i=1; i<=18; i++)
	{
		if((i%3) != 0){
			if(isxdigit(*p)){
				*q++ = *p++;
			}else{
				return (-1);
			}
		}else{
			if(i==18){
				break;
			}
			if(*p==':' || *p=='-'){
				p++;
			}else{
				return (-1);
			}
		}
	}
	*q = 0;
	PackBCD(local,pk,12);
	return 0;
}

int PackBCD(char *InBuf, UCHAR *OutBuf, int Len)
{
	int rc;
	register int ActiveNibble;
	char CharIn;
	UCHAR CharOut;

	rc = 0;
	ActiveNibble = 0;
	for(;(Len>0);Len--,InBuf++){
		CharIn = *InBuf;
		if(!isxdigit(CharIn)){
			rc = -1;
			break;
		}else{
			if(CharIn > '9'){
				CharIn += 9;
			}
		}
		if(rc == 0){
			CharOut = *OutBuf;
			if(ActiveNibble){
				*OutBuf++ = ((UCHAR)(CharOut&0xF0))|(CharIn&0x0F);
			}else{
				*OutBuf = ((UCHAR)(CharOut&0x0F))|((CharIn&0x0F)<<4);
			}
			ActiveNibble ^= 1;
		}
	}
	return rc;
}

int _UnpackBCD(UCHAR *InBuf, UCHAR *OutBuf, int Len)
{
	int rc = 0;
	UCHAR ch;
	register int i, active = 0;

	for( i=0; i<Len; i++)
	{
		ch = *InBuf;
		if(active){
			(*OutBuf = (ch&0x0f))<10 ? (*OutBuf+='0') : (*OutBuf+=('A'-10));
			InBuf++;
		}else{
			(*OutBuf = (ch&0xF0)>>4)<10 ? (*OutBuf+='0') : (*OutBuf+=('A'-10));
		}
		active ^= 1;
		if(!isxdigit(*OutBuf)){
			rc = -1;
			break ;
		}
		OutBuf++;
	}

	return rc;
}

int UnpackBCD(UCHAR *InBuf, UCHAR *OutBuf, int Len)
{
	return _UnpackBCD(InBuf,OutBuf,Len);
}

USHORT hex2short(UCHAR *p)
{
	USHORT s;
	s = *p++;
	s  = (s<<8) | *p++;
	return s;
}

UCHAR *short2hex(USHORT s, UCHAR *p)
{
	*p ++ = (s>>8) &0xff;
	*p ++ = s & 0xff;
	return p;
}

int isBufferPrint(char *buffer, int len)
{
	int i;
	for(i=0;(i<len) && (isprint(buffer[i]));i++);
	return (i == len);
}

int HexDumpOneLine(FILE *fp, UCHAR *buffer, int *len, int *line){
	register int i;
	fprintf(fp,"0x%06x [",*line);
	for(i=0; i<LINE_LEN;i++,(*len)--){
		(*len)>0?fprintf(fp,"%02X ",buffer[i]):fprintf(fp,"   ");
	}
	fprintf(fp,"] [");
	(*len) += LINE_LEN;
	for(i=0; i<LINE_LEN;i++,(*len)--){
		if(*len>0){
			isprint(buffer[i])?fputc(buffer[i],fp):fputc('.',fp);;
		}else{
			fputc(' ',fp);
		}
	}
	fprintf(fp,"]\n");

	return 0;
}

int HexDumpBuffer(FILE *fp,UCHAR *buffer, int length)
{
	int line = 0,len = length;
//	time_t timep;
//	time(&timep);
//	fprintf(fp,"%s",ctime(&timep));
	for(line=0;line<length/LINE_LEN+(length%LINE_LEN?1:0);++line)
	{
		HexDumpOneLine(fp,buffer,&len,&line);
		buffer+=LINE_LEN;
	}
	return 0;
}


