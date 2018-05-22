#include "mgrSvr.h"

int IcOpenDevice(void) {
	int icdev;

	if ((icdev = gmn_ic_init()) < 0) {
		return -1;
	}
	return icdev;
}

int IcCloseDevice(int icdev) {
	return ic_exit(icdev);
}

int IcResetDevice(int icdev, char *devid) {
	UCHAR icRead[256];
	int i;

	memset(icRead, 0xff, sizeof(icRead));
	if (cpu_reset(icdev, icRead) != 0) {
		return -1;
	}

	for (i = 0; i < sizeof(icRead); i++) {
		if ((icRead[i] == 0xff) && (icRead[i + 1] == 0xff)
				&& (icRead[i + 2] == 0xff)) {
			break;
		}
	}
	UnpackBCD(icRead, (UCHAR*) devid, i * 2);
	*(devid + i * 2) = 0;
	return 0;
}

unsigned char makeLRC(unsigned char *buffer, int len) {
	unsigned char lrc = 0;
	int i;

	/* make chk_sum */
	for (i = 0; i < len; i++) {
		lrc ^= buffer[i];
	}

	return lrc;
}

unsigned char gen_bcc(unsigned char *buf, int len) {
	return makeLRC(buf, len);
}

int IcCmd(int icdev, char *cmd_type, char *cmd, int cmd_len, char *resp) {
	UCHAR icWrite[256], icRead[256];
	UCHAR *p;
	int len;

	p = icWrite;
	PackBCD(cmd_type, p, 4);
	p += 2;
	*p++ = cmd_len;
	PackBCD(cmd, p, cmd_len * 2);
	p += cmd_len;
	*p = gen_bcc(icWrite, p - icWrite);
	p++;

	if ((cpu_comres(icdev, p - icWrite, icWrite, icRead)) != 0) {
		dv_beep(icdev, LONG_BEEP);
		return -2;
	}

	p = icRead;
	if (memcmp(p, icWrite, 2)) {
		dv_beep(icdev, LONG_BEEP);
		return -2;
	}
	p += 2;
	len = *p++;
	UnpackBCD(p, (UCHAR *) resp, len * 2);
	return 0;
}

int IcSelectFile(int icdev, char *p12, char *fd, int fdlen, char *reply) {
	char buf[256];
	int slen;

	memcpy(buf, "00A4", 4);
	memcpy(buf + 4, p12, 4);
	sprintf(buf + 8, "%02d", fdlen);
	memcpy(buf + 10, fd, fdlen * 2);
	slen = 2 + 2 + 1 + fdlen;

	printf("文件查询: ");
	if ((IcCmd(icdev, "0040", buf, slen, reply)) < 0) {
		return -1;
	}
	return 0;
}

int cpu_protocol(int icdev, int len, unsigned char *send_cmd,
		unsigned char *receive_data) {

	unsigned char send_buffer[1000];
	unsigned char receive_buffer[1000];
	int i, st, mytry, offset;

	mytry = 0;
	offset = 3;
	send_buffer[0] = PC_HEAD;
	send_buffer[1] = CMD_PTL;
	send_buffer[2] = 0x80;
	send_buffer[3] = 5 + len;
	send_buffer[4] = CPU_CARD;
	send_buffer[5] = 0x00;
	send_buffer[6] = 0x00;
	send_buffer[7] = 0x00;
	send_buffer[8] = 0x00;
	memcpy(send_buffer + 9, send_cmd, len);
	send_buffer[9 + len] = cr_bcc(9, send_buffer);

repeat:
	////
	HexDumpBuffer(stdout, send_buffer, 10 + len);

	st = send_com(icdev, 10 + len, send_buffer);
	if (st != OP_OK) {
		if (mytry++ < 2)
			goto repeat;
		else
			return st;
	}
	memset(receive_buffer, 0xff, sizeof(receive_buffer));

	st = receive_com(icdev, receive_buffer);
	////
	HexDumpBuffer(stdout, receive_buffer, 4 + receive_buffer[3]);

	if (st != OP_OK) {
		if (mytry++ < 2)
			goto repeat;
		else
			return st;
	}
	if (receive_buffer[1] != 0) {
		if (mytry++ < 2)
			goto repeat;
		else
			return -receive_buffer[1];
	}
	i = receive_buffer[2 + 4];
	if (receive_buffer[i + 1 + 4] == 0x6c) {
		mytry = 0;
		len = 9;
		send_buffer[0] = PC_HEAD;
		send_buffer[1] = CMD_PTL;
		send_buffer[2] = 0x80;
		send_buffer[3] = 5 + len;
		send_buffer[4] = CPU_CARD;
		send_buffer[5] = 0x00;
		send_buffer[6] = 0x00;
		send_buffer[7] = 0x00;
		send_buffer[8] = 0x00;
		send_buffer[9] = send_cmd[0];
		if (send_cmd[1] == 0)
			send_buffer[10] = 0x40;
		else
			send_buffer[10] = 0;
		send_buffer[11] = 5;
		memcpy(&send_buffer[12], "\x00\xc0\x00\x00", 4);
		send_buffer[12 + 4] = receive_buffer[i + 2 + 4];
		send_buffer[12 + 5] = cr_bcc(8, &send_buffer[9]);
		send_buffer[12 + 6] = cr_bcc(9, send_buffer);
		if (i > 2) {
			memcpy(&receive_data[offset], &receive_buffer[4 + 3], i - 2);
			offset = offset + i - 2;
		}
		goto repeat;
	} else if (receive_buffer[i + 1 + 4] == 0x61) {
		mytry = 0;
		len = 9;
		send_buffer[0] = PC_HEAD;
		send_buffer[1] = CMD_PTL;
		send_buffer[2] = 0x80;
		send_buffer[3] = 5 + len;
		send_buffer[4] = CPU_CARD;
		send_buffer[5] = 0x00;
		send_buffer[6] = 0x00;
		send_buffer[7] = 0x00;
		send_buffer[8] = 0x00;

		send_buffer[9] = send_cmd[0];
		if (send_cmd[1] == 0)
			send_buffer[10] = 0x40;
		else
			send_buffer[10] = 0;
		send_buffer[11] = 5;
		memcpy(&send_buffer[12], "\x00\xc0\x00\x00", 4);
		send_buffer[12 + 4] = receive_buffer[i + 2 + 4];
		send_buffer[12 + 5] = cr_bcc(8, &send_buffer[9]);
		send_buffer[12 + 6] = cr_bcc(9, send_buffer);
		if (i > 2) {
			memcpy(&receive_data[offset], &receive_buffer[4 + 3], i - 2);
			offset = offset + i - 2;
		}
		goto repeat;
	}

	memcpy(receive_data + offset, receive_buffer + 4 + 3, receive_buffer[3]);
	receive_data[0] = receive_buffer[4];  //NAD
	receive_data[1] = receive_buffer[5];  //PCB
	receive_data[2] = receive_buffer[6] + (unsigned char) offset - 3; //len
	return OP_OK;

}

int icReadEF(int icdev, int offset, UCHAR *icRead, int rdLen, UCHAR *resp) {
	unsigned char cmd[16], reply[256];
	int len;
	unsigned char *p;

	p = cmd;
	memcpy(p, "\x00\x40", 2);
	p += 2;
	*p++ = 2 + 2 + 1;
	/* Update Binary */
	memcpy(p, "\x00\xB0", 2);
	p += 2;
	/* Offset */
	p = short2hex(offset, p);
	*p++ = rdLen;
	*p = gen_bcc(cmd, p - cmd);
	p++;
	printf("数据查询: ");
	if (cpu_protocol(icdev, p - cmd, cmd, reply) != 0)
	//if(cpu_comres(icdev,p-cmd,cmd,reply)!=0)
	{
		dv_beep(icdev, LONG_BEEP);
		return -1;
	}
	p = reply;
	p += 2;
	len = *p++ - 2;
	memcpy(icRead, p, len);
	p += len;
	UnpackBCD(p, resp, 4);
	*(resp + 4) = 0;
	if (!memcmp(resp, "9000", 4))
		return 0;
	else
		return -2;
}

int IcReadEF(int icdev, int offset, UCHAR *icRead, int rdLen, UCHAR *resp) {
	int i, rc;

	for (i = 0; rdLen > LEN_ICIO; rdLen -= LEN_ICIO, i++) {
		rc = icReadEF(icdev, offset, icRead + i * LEN_ICIO, LEN_ICIO, resp);
		if (rc < 0) {
			return rc;
		}
		offset += LEN_ICIO;
	}
	if (rdLen) {
		rc = icReadEF(icdev, offset, icRead + i * LEN_ICIO, rdLen, resp);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

int IcReadIdentity(int icdev, icInfo_t *id, char *reply) {
	//Select MF
	if ((IcSelectFile(icdev, "0000", "3F00", 2, reply)) < 0) {
		return -1;
	}
	if ((IcSelectFile(icdev, "0000", "0010", 2, reply)) < 0) {
		return -1;
	}
	if ((IcSelectFile(icdev, "0200", "0011", 2, reply)) < 0) {
		return -1;
	}
	if ((IcReadEF(icdev, 0, (UCHAR *) id, sizeof(icInfo_t), (UCHAR *) reply))
			< 0) {
		return -1;
	}

	if(memcmp(id->vendor_id,IDENT_STRING,16)){
		return -1;
	}
	return 0;
}

int icVerifyPIN(int icdev, char *pin, int len, char *reply) {
	char buf[256];
	char expand_pin[80];
	int slen;

	UnpackBCD((uchar*) pin, (uchar*)expand_pin, len * 2);
	memcpy(buf, "00200000", 8);
	sprintf(buf + 8, "%02X", len);
	memcpy(buf + 8 + 2, expand_pin, len * 2);
	slen = 4 + 1 + len;

	printf("验证PIN: ");
	/*"0020000006313233343536", 11,*/
	if (IcCmd(icdev, "0040",buf, slen, reply) < 0) {
		return (-1);
	}
	if (memcmp(reply, "9000", 4))
		return (-1);
	return 0;
}

int IcVerifyPIN(int icdev, char *pin, int len, char *reply)
{

	/* Select MF */
	if(IcSelectFile(icdev, "0000", "3F00", 2, reply)<0)
	{
		return (-1);
	}

	/* Select DF */
	if(IcSelectFile(icdev, "0000", "0010", 2, reply)<0)
	{
		return (-1);
	}

	return icVerifyPIN( icdev, pin, len, reply);
}

int IcReadData(int icdev, int offset, char *pin, unsigned char *data, int len,char *reply)
{

	/* Select MF */
	if (IcSelectFile(icdev, "0000", "3F00", 2, reply) < 0) {
		return (-1);
	}

	/* Select DF */
	if (IcSelectFile(icdev, "0000", "0010", 2, reply) < 0) {
		return (-2);
	}

	if (icVerifyPIN(icdev, pin, strlen(pin), reply) < 0) {
		return (-3);
	}

	/* Select EF */
	if (IcSelectFile(icdev, "0200", "0012", 2, reply) < 0) {
		return (-4);
	}

	/* Read EF */
	if (IcReadEF(icdev, offset, data, len, (uchar*) reply) < 0) {
		return (-5);
	}

	return 0;
}

int ResetCardDevice(int fd, int icdev)
{
	int lang = HsmGetLanguage();
	char buffer[256];
	char resp[80];

	if((IcResetDevice(icdev,resp)) < 0)
	{
		if(lang){
			message(fd,buffer,"为插卡, 卡不可识别或卡已损坏.");
		}else{
			message(fd,buffer,"UNIDENTIFIED CARD OR CARD IS DANAGED.");
		}
		dv_beep(icdev,LONG_BEEP);
		return (-1);
	}
	return (0);
}

/* Check Management Key from Smart Card */
int IcCheckMgrKey(int icdev, char *pin, char *passwd, int *len, char *reply)
{
//	struct mgrIcCard_t mgrCard;
//	uchar mdc[16], cv[8];
//	uchar cmd5[MD5_DIGEST_LENGTH];
//
//	if( IcReadData(icdev, 0, pin, (uchar *)&mgrCard, sizeof(struct mgrIcCard_t), reply) < 0 )
//	{
//		return (-1);
//	}
//
//	/* Generated the management card check */
//	mdc_4(mgrCard.passwd, MD5_DIGEST_LENGTH, mdc);
//
//	/* The ExORed key encrypt 64 bits '0' */
//	_CheckValueDKey(mdc, cv);
//
//	/* Check the management card validality */
//	if(memcmp(mgrCard.cv,cv,sizeof(cv)))
//	{
//		return (-2);
//	}
//
//	/* Generate the password check value according to MD5 */
//	MD5((uchar*)passwd, *len, cmd5);
//
//	/* If the generated password is not the same with stored on card */
//	if(memcmp(cmd5, mgrCard.passwd, MD5_DIGEST_LENGTH))
//	{
//		return (-3);
//	}
//
	return 0;
}

