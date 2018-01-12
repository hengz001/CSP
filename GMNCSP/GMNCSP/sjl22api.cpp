#include "stdafx.h"
#include "sjl22api.h"

int sjl22Inform(int cmdid, int msghdlen, char *msghd, char *chkvalue, char *version) {
	char *p, *q, *cmd;
	char retBuf[MAX_MSGDATA];
	int cmdLen, retLen, rec;

	//
	if (cmdid<0) {
		return -1;
	}

	//
	cmd = (char *)malloc(msghdlen
		+ 2
		+ 1);
	if (NULL == cmd) {
		return -1;
	}

	p = cmd;
	memcpy(p, msghd, msghdlen);
	p += msghdlen;

	*p++ = 'N';
	*p++ = 'C';
	*p = 0x00;

	//
	cmdLen = p - cmd;

	//
	rec = HsmCmdRun(cmdid, msghdlen, msghd, cmd, cmdLen, retBuf, &retLen);
	free(cmd);

	//
	if (rec < 0)
	{
		return (rec);
	}

	//
	q = retBuf;
	*(q + retLen) = 0x00;
	printf("RECEIVE: %s\n", q);
	return 0;
}