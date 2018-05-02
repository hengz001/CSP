#include "mgrSvr.h"

struct termios nport, oport;
static int term_flg = 0;
struct icCfg_str icCfg;
char Reader_Type = 0;

unsigned char cr_bcc(int len, unsigned char *bcc_buffer)
{
	UCHAR lrc = 0;
	int i;

	for (i = 0; i < len; i++) {
		lrc ^= bcc_buffer[i];
	}
	return lrc;
}

int ck_bcc(int len, unsigned char *bcc_buffer) {
	unsigned char bcc = 0;
	bcc = cr_bcc(len, bcc_buffer);
	if (bcc == 0)
		return (OP_OK);
	else
		return (ERR_BCC);
}

int _receive_data(int icdev, unsigned char *s, int timer) {
	int st;
	clock_t start, end;

	start = clock();
	while (1) {
		st = read(icdev, s, 1);
		if (st > 0)
			return OP_OK;
		else {
			end = clock();
			if (((end - start) / CLOCKS_PER_SEC) > timer)
				return ERR_TIMEOUT;
		}
	}
	return (OP_OK);
}

int receive_data(int icdev, unsigned char *s) {
	return _receive_data(icdev, s, TIME_LIMITA);
}

int receive_data_2k(int icdev, unsigned char *s) {
	return _receive_data(icdev, s, TIME_LIMITB);
}

int receive_com(int icdev, unsigned char *receive_buffer) {
	int i = 0, temp, st;

	st = receive_data_2k(icdev, &receive_buffer[0]);
	if (st != OP_OK)
		return (st);
	if (receive_buffer[0] != DEV_HEAD)
		return (ERR_READ);

	st = receive_data(icdev, &receive_buffer[1]);
	if (st != OP_OK)
		return (st);
	st = receive_data(icdev, &receive_buffer[2]);
	if (st != OP_OK)
		return (st);
	st = receive_data(icdev, &receive_buffer[3]);
	if (st != OP_OK)
		return (st);
	for (i = 0; i < receive_buffer[3] + 1; i++) {
		st = receive_data(icdev, &receive_buffer[4 + i]);
		if (st != OP_OK)
			return (st);
	}

	temp = ck_bcc(receive_buffer[3] + 5, receive_buffer);
	if (temp == 0)
		return (OP_OK);
	else
		return (ERR_CHECK);
}

//向IC读卡器写入字符
int sendchar(int icdev, unsigned char data) {
	int st;

	if (term_flg) {
		st = write(icdev, &data, 1);
		if (st > 0)
			return st;
		else
			return ERR_WRITE;
	} else {
		st = write(icdev, icCfg.AUXSTARTWRITE,
				strlen((char *) icCfg.AUXSTARTWRITE));
		if (st <= 0)
			return st;
		st = write(icdev, &data, 1);
		if (st <= 0)
			return st;
		st = write(icdev, icCfg.AUXENDWRITE,
				strlen((char *) icCfg.AUXENDWRITE));
		return st;
	}
}

int send_com(int icdev, int len, unsigned char *send_buffer) {
	int i;
	int st;
	for (i = 0; i < len; i++) {
		st = sendchar(icdev, send_buffer[i]);
		if (st <= 0)
			return ERR_WRITE;
	}
	return OP_OK;
}

int srd_ver(int icdev, int len, unsigned char *data_buffer) {
	unsigned char send_buffer[160];
	unsigned char receive_buffer[160];
	int st;

	if ((len != 10) && (len != 18))
		return ERR_LEN;
	send_buffer[0] = PC_HEAD;
	send_buffer[1] = CMD_RDVER;
	send_buffer[2] = 0x00;
	send_buffer[3] = 7;
	send_buffer[4] = COMUNAL;
	send_buffer[5] = 0x00;
	send_buffer[6] = 0x00;
	send_buffer[7] = 0x00;
	send_buffer[8] = 0x00;
	send_buffer[9] = 0x00;
	send_buffer[10] = (unsigned char) len;
	send_buffer[11] = cr_bcc(11, send_buffer);

	///////
	printf("开启读卡器: ");
	HexDumpBuffer(stdout, send_buffer, 12);
	st = send_com(icdev, 12, send_buffer);
	if (st != OP_OK)
		return (st);

	st = receive_com(icdev, receive_buffer);
	if (st != OP_OK)
		return (st);
	///////
	HexDumpBuffer(stdout, receive_buffer, 4+receive_buffer[3]);

	if (receive_buffer[1] != OP_OK)
		return (-receive_buffer[1]);
	if (len > receive_buffer[3])
		len = receive_buffer[3];
	memcpy(data_buffer, receive_buffer + 4, len);
	if (memcmp((char *) data_buffer, "RDSPC", 5) == 0)
		Reader_Type = 1;
	return (OP_OK);
}

void SetIcCardParm(void) {
	memset(&icCfg, 0, sizeof(icCfg));
	//get_s(line,icCfg.DRVCOMM);端口COM4
	strcpy((char *) icCfg.DRVCOMM, ICCARD_PORT);
	//case 'S':get_s(line,icCfg.SETAUX);break;
	strcpy((char *) icCfg.SETAUX, "'!11;0;0;0Y'[20h'[12h");
	//case 'I':get_s(line,icCfg.INITAUX);break;
	strcpy((char *) icCfg.INITAUX, "'[/50h'[/53h'[/54l");
	//case 'C':get_s(line,icCfg.CLOSEAUX);break;
	strcpy((char *) icCfg.CLOSEAUX, "'[/50l");
	//case 'A':get_s(line,icCfg.AUXENDWRITE);break;
	strcpy((char *) icCfg.AUXENDWRITE, "'[/50l");
	//case 'W':get_s(line,icCfg.AUXSTARTWRITE);break;
	strcpy((char *) icCfg.AUXSTARTWRITE, "'[/51h");
	//case 'D':get_s(line,icCfg.DISABLEKEYBOARD);break;
	strcpy((char *) icCfg.DISABLEKEYBOARD, "'[2h");
	//case 'E':get_s(line,icCfg.ENABLEKEYBOARD);break;
	strcpy((char *) icCfg.ENABLEKEYBOARD, "'[2l");
	term_flg = 1;
}

int ic_exit(int fd) {
	if (!term_flg)
		write(fd, icCfg.CLOSEAUX, strlen((char *) icCfg.CLOSEAUX));
	tcsetattr(fd, TCSANOW, &oport);
	close(fd);
	return 0;
}

int gmn_ic_init(void) {
	int fd, st;
	unsigned char dv_ver[10];
	long int baud = 9600;

	/* Read configuration file */
	SetIcCardParm();

	fd = open((char *) icCfg.DRVCOMM, O_RDWR | O_NOCTTY);
	if (fd < 0)
		return (ERR_OPENCOMM);

	tcgetattr(fd, &nport);	//获取终端参数
	oport = nport;
	memset(&nport, 0, sizeof(nport));
	switch (baud) {
	case 9600:
		nport.c_cflag = B9600;
		break;
	case 19200:
		nport.c_cflag = B19200;
		break;
	case 38400:
		nport.c_cflag = B38400;
		break;
	case 57600:
		nport.c_cflag = B57600;
		break;
	case 115200:
		nport.c_cflag = B115200;
		break;
	default:
		nport.c_cflag = B9600;
		break;
	}
	nport.c_cflag |= (CREAD | CLOCAL | CS8 | CSTOPB);
	nport.c_lflag |= (ISIG | IGNPAR);
	tcsetattr(fd, TCSANOW, &nport);
	tcflush(fd, TCIFLUSH);
	tcflush(fd, TCOFLUSH);

	st = srd_ver(fd, 10, dv_ver);
	if (st != OP_OK) {
		ic_exit(fd);
		return ERR_COMM;
	}
	if (strncmp((char *) dv_ver, "RDSPC", 5) == 0)
		Reader_Type = 1;
	return fd;
}
