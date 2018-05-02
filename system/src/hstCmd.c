#include "tcpSvr.h"

typedef	int (*function)(int cst, int mca, int sca, int dca, char *i_buf, int ilen, char *o_buf, int *olen);

typedef struct
{
	/* Command Code */
	char cmd_code[3];
	/* Function Name */
	function cmd;
	/* Authorised State */
	int  checkauth;
} racalFunc_t;

typedef struct
{
	/* Command Code */
	char cmd_code[3];
	/* Function Name */
	int  cmd;
} racalExpCmd_t;


static racalFunc_t hsm_racal_expcmd[] =
{
		{"NC",		NC,		 0},
		{"EH",		EH,		 0},
		{"",		0,		-1}
};

enum{
	EXP_CMD_NC = 1,
	EXP_CMD_NC1,
	EXP_CMD_NC2,
	EXP_CMD_NC3,
};

static racalExpCmd_t hstExpCmd[] =
{
		{	"NC", EXP_CMD_NC},
		{	"",			  -1}
};

/* Handle multi crypto algorithm identity block */
int HandleMultiAlgoIdentidyBlock(int cst, unsigned char **buf, int *len,int *mca, int *sca, int *dca)
{
	unsigned char *p = *buf;

	// Fixed bug on binary data prefixed by P - GMN01042006Ro
	if (isBufferDec((char*) p + 1, 2)) {
		p += 1;		// 'T'

		*sca = *p - '0';
		p += 1;
		/* Source Crypto algorithm */
		switch (*sca) {
		case ALGO_DESTDES:
		case ALGO_AES:
		case ALGO_SM4:
		case ALGO_SSF33:
		case ALGO_SSF10:
		case ALGO_SM1:
		case ALGO_SM9:		//20171226add
			break;
		default:
			return (51);
		}

		*dca = *p - '0';
		p += 1;
		/* Destination Crypto algorithm */
		switch (*dca) {
		case ALGO_DESTDES:
		case ALGO_AES:
		case ALGO_SM4:
		case ALGO_SSF33:
		case ALGO_SSF10:
		case ALGO_SM1:
		case ALGO_SM9:		//20171226add
			break;
		default:
			return (51);
		}
		*len -= 3;
		*buf = p;
	}
	return 0;
}

int hsmCmdInterpret(int cst, int protocol, UCHAR *i_buf, int ilen, UCHAR *o_buf, int *olen, int *prt_cmd)
{
	UCHAR *p, *q;
	int rc = 0;
	int found = 0;
	racalFunc_t *cmdp;

	int mca = protocol;
	int sca = ALGO_DESTDES;
	int dca = ALGO_DESTDES;
	p = i_buf, q = o_buf;

	for(cmdp = hsm_racal_expcmd; *cmdp->cmd; cmdp++){
		if(!memcmp(i_buf,cmdp->cmd_code,LEN_CMDLEN)){

			if(cmdp->checkauth && !isHsmAuthorized()){
				return error_return (17,(char *)o_buf+LEN_CMDLEN,olen);
			}

			found = 1;
			p += LEN_CMDLEN;
			q += LEN_CMDLEN;

			if(*p == 'p'){
				if((rc = HandleMultiAlgoIdentidyBlock(cst,&p,&ilen,&mca,&sca,&dca)) != 0)
				{
					return error_return(rc,(char *)q,olen);
				}
			}
			rc = (*cmdp->cmd)(cst,mca,sca,dca,(char*)p,ilen,(char*)q,olen);
			break;
		}
	}

	if(!found){
		return error_return(29,(char *)o_buf+LEN_CMDLEN,olen);
	}
	return (rc);
}


int WhatExpCmd(UCHAR *cmdcode)
{
	static racalExpCmd_t *cmdp;

	for(cmdp=hstExpCmd; cmdp->cmd; cmdp++){
		if(!(memcmp(cmdcode,cmdp->cmd_code,LEN_CMDCODE))){
			return cmdp->cmd;
		}
	}
	return -1;
}

UCHAR *getHostCmdString(UCHAR *pBuf, int len, int charset)
{
	UCHAR *p;
	static UCHAR cmd[1+48];
	if(charset!=CHARSET_ASCII){
		EbcdicToAscii(pBuf,cmd,len);
		p = cmd;
	}else{
		p = pBuf;
	}
	return p;
}

int PreproExpCmd(int proto, UCHAR *buf, int len, int charset)
{
	UCHAR *p = buf, *s;
	int op;

	if(charset != CHARSET_ASCII){
		EbcdicToAscii(p,p,LEN_CMDCODE);
	}

	if((op = WhatExpCmd(p)) < 0){
		return (29);
	}
	p += LEN_CMDCODE;
	s = getHostCmdString(p,3,charset);
	if(*s == 'P')
	{
		if(isBufferDec((char*)s+1,2)){
			if(charset !=  CHARSET_ASCII)
			{
				EbcdicToAscii(p,p,3);
			}
		}
	}
	return 0;
}

int isHostCmd(racalFunc_t *hsmCmd, UCHAR *cmdcode)
{
	static racalFunc_t *cmdp;
	for(cmdp=hsmCmd;*cmdp->cmd;cmdp++){
		if(!(memcmp(cmdcode,cmdp->cmd_code,LEN_CMDCODE))){
			return TRUE;
		}
	}
	return FALSE;
}

int isExpCmd(UCHAR *buf, int charset)
{
	return isHostCmd ( hsm_racal_expcmd, getHostCmdString(buf, LEN_CMDCODE, charset) );
}
