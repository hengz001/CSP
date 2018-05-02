#include "mgrSvr.h"

struct baudrate_t
{
	int	cfg_baudrate;
	int	baudrate;
};

struct baudrate_t  BaudRate[] =
{
	{200,		B200	},	/* 0000006 */
	{300,		B300	},	/* 0000007 */
	{600,		B600	},	/* 0000010 */
	{1200,		B1200	},	/* 0000011 */
	{2400,		B2400	},	/* 0000013 */
	{4800,		B4800	},	/* 0000014 */
	{9600,		B9600	},	/* 0000015 */
	{19200,		B19200	},	/* 0000016 */
	{38400,		B38400	},	/* 0000017 */
	{57600,		B57600	},	/* 0000021 */
	{115200,	B115200	},	/* 0000023 */
	{0,		B0}		/* 0       */
};

word_format_t portParm[] =
{
	{0,		0,		0},	/* 7 bits, no parity, 1 stop */
	{CS7,	0,		0},	/* 7 bits, no parity, 1 stop */
	{CS7,	PARODD,	0},	/* 7 bits, odd parity, 1 stop */
	{CS7,	PARENB,	0},	/* 7 bits, even parity, 1 stop */
	{CS8,	0,		0},	/* 8 bits, no parity, 1 stop */
	{CS8,	PARODD,	0},	/* 8 bits, odd parity, 1 stop */
	{CS8,	PARENB,	0},	/* 8 bits, even parity, 1 stop */
	{-1,	-1,		-1}
};

int GetCfgBaudRate(int baudrate)
{
	struct baudrate_t  *pB;
	int  selBaud;

	for(pB = BaudRate, selBaud = 0; pB->baudrate; pB++, selBaud++)
	{
		if(pB->baudrate==baudrate)
		{
			return selBaud;
		}
	}
	return (-1);
}

int GetCfgWordFormat(word_format_t *parm)
{
	word_format_t *pW;
	int  selWord;

	for(pW = portParm, selWord = 0; pW->csize>=0; pW++, selWord++)
	{
		if(pW->csize==parm->csize&&pW->parity==parm->parity&&pW->stopbit==parm->stopbit)
		{
			return selWord;
		}
	}
	return (-1);
}


int AA(int fd, int *display)
{
	return 0;
}


