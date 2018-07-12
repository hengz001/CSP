
#include "common.h"
#include "tools.h"

#define LINE_LEN 16

int HexDumpOneLine(FILE *fp, unsigned char *buffer, int *len, int *line)
{
	register int i;
	fprintf(fp, "%06X | ", *line);
	for (i = 0; i<LINE_LEN; i++, (*len)--)
	{
		(*len > 0) ? fprintf(fp, "%02X", buffer[i]) : fprintf(fp, "  ");
	}
	*len += LINE_LEN;
	fprintf(fp, "| ");

	for (i = 0; i<LINE_LEN; i++, (*len)--)
	{
		if (*len > 0)
		{
			isprint(buffer[i]) ? fputc(buffer[i], fp) : fputc('.', fp);
		}
		else
		{
			fputc(' ', fp);
		}
	}
	fprintf(fp, "|\n");
	return 0;
}

int HexDumpBuffer(FILE *fp, unsigned char *buffer, int length)
{
	int len = length;
	int line = 0;
	for (; line<(length / LINE_LEN + (length%LINE_LEN ? 1 : 0)); line++)
	{
		HexDumpOneLine(fp, buffer, &len, &line);
		buffer += LINE_LEN;
	}
	return 0;
}

int PackBCD(char *inBuf, unsigned char *outBuf, int len)
{
	char in, out;
	int active = 0;

	for (; len>0; len--, inBuf++)
	{
		in = *inBuf;
		out = *outBuf;
		if (!isxdigit(in))
		{
			return -1;
		}

		if (in > '9')
		{
			in += 9;
		}

		if (active)
		{
			*outBuf++ = (unsigned char)((out & 0xF0) | (in & 0x0F));
		}
		else
		{
			*outBuf = (unsigned char)((out & 0x0F) | (in & 0x0F) << 4);
		}
		active ^= 1;
	}


	return 0;
}

int UnPackBCD(unsigned char *inBuf, char *outBuf, int len)
{
	int active = 0;

	for (; len>0; len--, outBuf++)
	{
		if (active)
		{
			(*outBuf = (*inBuf & 0x0F)) < 10 ? (*outBuf += '0') : (*outBuf += ('A' - 10));
			inBuf++;
		}
		else
		{
			(*outBuf = (*inBuf & 0xF0) >> 4) < 10 ? (*outBuf += '0') : (*outBuf += ('A' - 10));
		}
		active ^= 1;
	}
	return 0;
}
