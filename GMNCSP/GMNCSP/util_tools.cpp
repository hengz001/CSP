#include "stdafx.h"
#include "hsmcmd.h"
#include "hsmdefs.h"

char HexToASCII(int ch)
{
	ch &= 0x0f;
	return (ch < 0x0a) ? (char)(ch += '0') : (char)(ch += 0x37);
}

char *strupper(char *str)
{
	char *p = str;
	for (; *p; p++)  *p = toupper(*p);
	return str;
}


unsigned char *int_to_byte2(int i, unsigned char *p)
{
	return short2hex((unsigned short)i, p);
}


unsigned char *short2hex(unsigned short s, unsigned char *p)
{
	*p++ = (s >> 8) & 0xff;
	*p++ = s & 0xff;

	return p;
}

unsigned char *long2hex(unsigned long l, unsigned char *p)
{
	*p++ = (unsigned char)((l >> 24) & 0xff);
	*p++ = (unsigned char)((l >> 16) & 0xff);
	*p++ = (unsigned char)((l >> 8) & 0xff);
	*p++ = (unsigned char)(l & 0xff);

	return p;
}


/* To judge the specified length of buffer if is hexadecimal or not */
int isBufferHex(char *buffer, int len)
{
	int i;
	for (i = 0; (i < len) && isxdigit((int)buffer[i]); i++);
	return(i == len);
}


/*** Convert hex char's buffer to integer e.g. 0F to 15, FFFF to 65535 ***/
int hex2int(unsigned char *buffer, int len)
{
	register int  rv = 0, i;
	register unsigned char *ptr;

	/* Check the buffer if it's all hexadecimal
*/
	if (!isBufferHex((char *)buffer, len))
	{
		return -1;
	}
	for (ptr = buffer, i = 0; i < len; i++, ptr++)
	{
		rv = rv * 16 + (((*ptr = toupper(*ptr)) > '9') ? (*ptr - 'A' + 10) : (*ptr - '0'));
	}
	return rv;
}


unsigned long hex2long(unsigned char *p)
{
	unsigned long l;
	l = *p++;
	l = (l << 8) | *p++;
	l = (l << 8) | *p++;
	l = (l << 8) | *p++;

	return l;
}

unsigned short hex2short(unsigned char *p)
{
	unsigned short s;
	s = *p++;
	s = (s << 8) | *p++;

	return s;
}

int CheckNum(char *str)
{
	unsigned int	i;

	for (i = 0; i < strlen(str); i++)
	{
		if ((str[i] < '0') || (str[i] > '9')) return(-1);
	}

	return(0);
}


int UnpackBCD(unsigned char *InBuf, char *OutBuf, int Len)
{

	int rc = 0;

	unsigned char ch;

	register int i, active = 0;

	for (i = 0; i < Len; i++)
	{

		ch = *InBuf;

		if (active)
		{
			(*OutBuf = (ch & 0xF)) < 10 ? (*OutBuf += '0') : (*OutBuf += ('A' - 10));
			InBuf++;
		}
		else
		{
			(*OutBuf = (ch & 0xF0) >> 4) < 10 ? (*OutBuf += '0') : (*OutBuf += ('A' - 10));
		}

		active ^= 1;

		if (!isxdigit(*OutBuf))	/* validate character */
		{
			rc = -1;
			break;
		}

		OutBuf++;

	}

	*OutBuf = 0;

	return (rc);

}

int PackBCD(char *InBuf, unsigned char *OutBuf, int Len)
{
	int	    rc;		/* Return Value */

	register int     ActiveNibble;	/* Active Nibble Flag */

	char     CharIn;	/* Character from source buffer */
	unsigned char   CharOut;	/* Character from target buffer */

	rc = 0;		/* Assume everything OK. */

	ActiveNibble = 0;	/* Set Most Sign Nibble (MSN) */
				/* to Active Nibble. */

	for (; (Len > 0); Len--, InBuf++)
	{
		CharIn = *InBuf;

		if (!isxdigit(CharIn))	/* validate character */
		{
			rc = -1;
		}
		else
		{
			if (CharIn > '9')
			{
				CharIn += 9;	/* Adjust Nibble for A-F */
			}
		}

		if (rc == 0)
		{

			CharOut = *OutBuf;
			if (ActiveNibble)
			{
				*OutBuf++ = (unsigned char)((CharOut & 0xF0) |
					(CharIn & 0x0F));
			}
			else
			{
				*OutBuf = (unsigned char)((CharOut & 0x0F) |
					((CharIn & 0x0F) << 4));
			}
			ActiveNibble ^= 1;	/* Change Active Nibble */
		}
	}

	return rc;

}


int CheckSchem(char schem)
{

	if ((schem != 'X') && (schem != 'Y') && (schem != 'U') && (schem != 'T') && (schem != 'Z')) return -1;
	else return 0;
}

int CheckAlgo(int algo)
{
	int i;

	i = algo / 10;

	if ((i != 0) && (i != 1) && (i != 2) && (i != 3) && (i != 4) && (i != 5)) return -1;

	i = algo % 10;

	if ((i != 0) && (i != 1) && (i != 2) && (i != 3) && (i != 4) && (i != 5)) return -1;

	return 0;
}


int GetIvLength(int algo)
{
	int   ivLen;
	switch (algo)
	{
	case 0:
	case 22:
	case 2:
		ivLen = 16;
		break;
	case 11:
	case 1:
	case 3:
	case 33:
	case 5:
	case 55:
		ivLen = 32;
		break;
	default:
		return (-51);
	}
	return (ivLen);
}

int GetKeyLen(char *key)
{
	if ((key[0] == 'i') || (key[0] == 'k')) return (4 + 1);

	if ((key[0] == 'I') || (key[0] == 'K')) return (3 + 1);

	if ((key[1] == 'i') || (key[1] == 'k')) return (4 + 1 + 1);

	if ((key[1] == 'I') || (key[1] == 'K')) return (3 + 1 + 1);

	if ((key[0] == 'X') || (key[0] == 'U')) return (32 + 1);

	if ((key[0] == 'Y') || (key[0] == 'T')) return (48 + 1);

	return 16;
}

int GetCvLength(char cvFlag)
{
	switch (cvFlag)
	{
	case 0:
		return 16;
	case 1:
	default:
		return 6;
	}
}



void GetByteNum(int bitnum, int *bytenum)
{
	*bytenum = bitnum / 8;

	if (bitnum % 8) (*bytenum)++;
}


int GetDerByteNum(unsigned char *DerBuffer, long *derbytenum)
{
	long i, j;

	unsigned char *p;

	unsigned long ret = 0;

	p = DerBuffer + 1;

	*derbytenum = 0;


	if (*DerBuffer != 0x30)
	{

		return (-1);
	}

	if (*p == 0x80)
	{
		return (-2);
	}
	else
	{
		i = *p & 0x7f;

		if (*p & 0x80)
		{
			if (i > sizeof(long))
			{
				return (-3);
			}

			j = i;

			while (i-- > 0)
			{
				ret <<= 8L;

				p++;

				ret |= *p;
			}

			ret = ret + j + 2;

		}
		else
		{
			ret = i + 2;
		}
	}

	if (ret > 0x400000) ret = 0;

	*derbytenum = (long)ret;

	return 0;
}



void rsaFormParmBlockOAEP(unsigned char **buf, int mgf, int mgfHash, int OAEP_parm_len, unsigned char *OAEP_parm)
{
	unsigned char *p = *buf;

	/* Mask generation function */
	sprintf((char *)p, "%02d", mgf);
	p += 2;

	/* MGF hash - SHA1 */
	sprintf((char *)p, "%02d", mgfHash);
	p += 2;

	/* Parameter length */
	sprintf((char *)p, "%02d", OAEP_parm_len);
	p += 2;

	/* Parameter */
	if (OAEP_parm_len > 0)
	{
		memcpy(p, OAEP_parm, OAEP_parm_len);
		p += OAEP_parm_len;
	}

	/* Delimeter */
	*p++ = ';';

	*buf = p;
}


void rsaFormParmBlockPSS(unsigned char **buf, int mgf, int mgfHash, int pssRule, int trailerField)
{
	unsigned char *p = *buf;

	/* Mask generation function */
	sprintf((char *)p, "%02d", mgf);
	p += 2;

	/* MGF hash - SHA1 */
	sprintf((char *)p, "%02d", mgfHash);
	p += 2;

	/* PSS salt length */
	sprintf((char *)p, "%04d", pssRule);
	p += 4;

	/* PSS trailer field */
	sprintf((char *)p, "%02d", trailerField);
	p += 2;

	/* Delimeter */
	*p++ = ';';

	*buf = p;
}



/* To judge the specified length of buffer if is decimal or not */
int isBufferDec(char *buffer, int len)
{
	int i;
	for (i = 0; (i < len) && isdigit((int)buffer[i]); i++);
	return(i == len);
}

/*** Convert decimal char's buffer to integer  */
int dec2int(unsigned char *buffer, int len)
{
	register unsigned int  rv = 0, i;
	register unsigned char *ptr;

	if (!isBufferDec((char *)buffer, len))
	{
		return -1;
	}
	for (ptr = buffer, i = 0; i < (unsigned int)len; i++, ptr++)
	{
		rv = rv * 10 + *ptr - '0';
	}
	return rv;
}



int Decode_PublicKey_Der(unsigned char *der_buf, int *bufLen, unsigned char *n, int *nlen, unsigned char *e, int *elen)
{
	unsigned char *p = der_buf;
	long  lenBytes = 0, len1 = 0, tlen = 0;

	/* Start of Sequence */
	if (*p++ != 0x30)
	{
		return -1;
	}

	if (*p < 0x80)
	{
		len1 = *p++ & 0x000000FF;
		lenBytes = 1;
	}
	else if (*p == 0x81)
	{
		p++;
		len1 = *p++ & 0x000000FF;
		lenBytes = 2;
	}
	else if (*p == 0x82)
	{
		p++;
		tlen = *p++ & 0x000000FF;
		/*                len1 = (*p++ << 8) & 0xff;
						len1+= *p++ & 0xff;
						*/
		len1 = ((tlen << 8) & 0x0000FF00) + (*p++ & 0x000000FF);
		lenBytes = 3;
	}
	else
	{
		return -2;
	}

	/* Start of Integer */
	if (*p++ != 0x02)
	{
		return -3;
	}

	/* Length of modulus */
	if (*p < 0x80)
	{
		*nlen = *p++ & 0x000000FF;
	}
	else if (*p == 0x81)
	{
		*p++;
		*nlen = *p++ & 0x000000FF;
	}
	else if (*p == 0x82)
	{
		*p++;
		/*                *nlen = (*p++ << 8) & 0xff;
						*nlen+=  *p++ & 0xff;
						*/
		tlen = *p++ & 0x000000FF;

		*nlen = ((tlen << 8) & 0x0000FF00) + (*p++ & 0x000000FF);
	}
	else
	{
		return -4;
	}

	/* Modulus */
	memcpy(n, p, *nlen);
	p += *nlen;

	/* Start of integer */
	if (*p++ != 0x02)
	{
		return -5;
	}

	/* exponent length */
	*elen = *p++ & 0x000000FF;

	/* exponent */
	memcpy(e, p, *elen);
	p += *elen;

	*bufLen = p - der_buf;

	if (*bufLen != len1 + lenBytes + 1)
	{
		return -6;
	}

	if (*nlen <= 0 || *elen <= 0)
	{
		return -7;
	}
	if (*elen > 0x7f)
	{
		return -8;
	}

	return 0;
}



int Encode_PublicKey_Der(unsigned char * n, int nlen, unsigned char * e, int elen, unsigned char *der_buf, int *bufLen)
{
	unsigned char *p = der_buf;
	int  lenBytes, len1, len2;

	if (nlen <= 0 || elen <= 0)
	{
		return -1;
	}
	if (elen > 0x7f)
	{
		return -1;
	}
	/* Start of Sequence */
	*p++ = 0x30;

	/* Der length */
	len2 = nlen;

	if (len2 < 0x80)
	{
		lenBytes = 1;
	}
	else if (len2 > 0x7f && len2 < 0x100)
	{
		lenBytes = 2;
	}
	else if (len2 > 0xff && len2 < 0x10000)
	{
		lenBytes = 3;
	}
	/* support only less than 0x10000
 */
	else
	{
		return -1;
	}

	if ((len1 = (1 + lenBytes + nlen + 1 + 1 + elen)) > 0x7f && len1 < 0x100)
	{
		*p++ = 0x81;
	}
	else if (len1 > 0xff && len1 < 0x10000)
	{
		*p++ = 0x82;
	}

	if (len1 < 0x100)
	{
		*p++ = len1;
	}
	else if (len1 > 0xff && len1 < 0x10000)
	{
		*p++ = (len1 >> 8) & 0xff;
		*p++ = len1 & 0xff;
	}

	/* Start of Integer */
	*p++ = 0x02;

	/* Length of modulus */
	if (nlen > 0x7f && nlen < 0x100)
	{
		*p++ = 0x81;
	}
	else if (nlen > 0xff && nlen < 0x10000)
	{
		*p++ = 0x82;
	}

	if (nlen < 0x100)
	{
		*p++ = nlen;
	}
	else if (nlen > 0xff && nlen < 0x10000)
	{
		*p++ = (nlen >> 8) & 0xff;
		*p++ = nlen & 0xff;
	}

	/* Modulus */
	memcpy(p, n, nlen);
	p += nlen;

	/* Start of integer */
	*p++ = 0x02;

	/* exponent length */
	*p++ = elen;

	/* exponent */
	memcpy(p, e, elen);
	p += elen;

	*bufLen = p - der_buf;
	return 0;
}




int Decode_ECPublicKey_Der(unsigned char *der_buf, int *bufLen, unsigned char *pubkey, int *pubkeylen)
{
	unsigned char *p = der_buf;
	long  lenBytes = 0, len1 = 0, tlen = 0;

	/* Start of Sequence */
	if (*p++ != 0x30)
	{
		return -1;
	}

	if (*p < 0x80)
	{
		len1 = *p++ & 0x000000FF;
		lenBytes = 1;
	}
	else if (*p == 0x81)
	{
		p++;
		len1 = *p++ & 0x000000FF;
		lenBytes = 2;
	}
	else if (*p == 0x82)
	{
		p++;
		tlen = *p++ & 0x000000FF;
		/*                len1 = (*p++ << 8) & 0xff;
						len1+= *p++ & 0xff;
						*/
		len1 = ((tlen << 8) & 0x0000FF00) + (*p++ & 0x000000FF);
		lenBytes = 3;
	}
	else
	{
		return -2;
	}

	/* Start of Integer */
	if (*p++ != 0x02)
	{
		return -3;
	}

	/* Length of modulus */
	if (*p < 0x80)
	{
		*pubkeylen = *p++ & 0x000000FF;
	}
	else if (*p == 0x81)
	{
		*p++;
		*pubkeylen = *p++ & 0x000000FF;
	}
	else if (*p == 0x82)
	{
		*p++;
		/*                *nlen = (*p++ << 8) & 0xff;
						*nlen+=  *p++ & 0xff;
						*/
		tlen = *p++ & 0x000000FF;

		*pubkeylen = ((tlen << 8) & 0x0000FF00) + (*p++ & 0x000000FF);
	}
	else
	{
		return -4;
	}

	/* Modulus */
	memcpy(pubkey, p, *pubkeylen);
	p += *pubkeylen;


	*bufLen = p - der_buf;

	if (*bufLen != len1 + lenBytes + 1)
	{
		return -6;
	}

	if (*pubkeylen <= 0)
	{
		return -7;
	}

	return 0;
}



int Encode_ECPublicKey_Der(unsigned char * pubkey, int pubkeylen, unsigned char *der_buf, int *bufLen)
{
	unsigned char *p = der_buf;
	int  lenBytes, len1, len2;

	if (pubkeylen <= 0)
	{
		return -1;
	}

	/* Start of Sequence */
	*p++ = 0x30;

	/* Der length */
	len2 = pubkeylen;

	if (len2 < 0x80)
	{
		lenBytes = 1;
	}
	else if (len2 > 0x7f && len2 < 0x100)
	{
		lenBytes = 2;
	}
	else if (len2 > 0xff && len2 < 0x10000)
	{
		lenBytes = 3;
	}
	/* support only less than 0x10000
 */
	else
	{
		return -1;
	}

	if ((len1 = (1 + lenBytes + pubkeylen + 1)) > 0x7f && len1 < 0x100)
	{
		*p++ = 0x81;
	}
	else if (len1 > 0xff && len1 < 0x10000)
	{
		*p++ = 0x82;
	}

	if (len1 < 0x100)
	{
		*p++ = len1;
	}
	else if (len1 > 0xff && len1 < 0x10000)
	{
		*p++ = (len1 >> 8) & 0xff;
		*p++ = len1 & 0xff;
	}

	/* Start of Integer */
	*p++ = 0x02;

	/* Length of modulus */
	if (pubkeylen > 0x7f && pubkeylen < 0x100)
	{
		*p++ = 0x81;
	}
	else if (pubkeylen > 0xff && pubkeylen < 0x10000)
	{
		*p++ = 0x82;
	}

	if (pubkeylen < 0x100)
	{
		*p++ = pubkeylen;
	}
	else if (pubkeylen > 0xff && pubkeylen < 0x10000)
	{
		*p++ = (pubkeylen >> 8) & 0xff;
		*p++ = pubkeylen & 0xff;
	}

	/* Modulus */
	memcpy(p, pubkey, pubkeylen);
	p += pubkeylen;

	*bufLen = p - der_buf;
	return 0;
}








