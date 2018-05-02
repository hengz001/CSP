#include "mgrSvr.h"

int cpu_reset(int icdev, UCHAR *data_buffer) {
	UCHAR send_buffer[1024];
	UCHAR receive_buffer[1024];
	int mytry, st;

	mytry = 0;
	send_buffer[0] = PC_HEAD;
	send_buffer[1] = CMD_RST;
	send_buffer[2] = 0x80;
	send_buffer[3] = 5;
	send_buffer[4] = CPU_CARD;
	send_buffer[5] = 0x00;
	send_buffer[6] = 0x00;
	send_buffer[7] = 0x00;
	send_buffer[8] = 0x00;
	send_buffer[9] = cr_bcc(9, send_buffer);

	repeat: st = send_com(icdev, 10, send_buffer);
	if (st != OP_OK) {
		if (mytry++ < 3) {
			goto repeat;
		}
		return st;
	}
//////
	printf("重设读卡器: ");
	HexDumpBuffer(stdout, send_buffer, 10);

	st = receive_com(icdev, receive_buffer);
	if (st != OP_OK) {
		if (mytry++ < 3) {
			goto repeat;
		}
		return st;
	}
	/////
	HexDumpBuffer(stdout, receive_buffer,4+receive_buffer[3]);

	if ((receive_buffer[1]) != 0) {
		if (mytry++ < 3) {
			goto repeat;
		}
		return (receive_buffer[1] * -1);
	} else {
		memcpy(data_buffer, receive_buffer + 4,
				receive_buffer[2] * 256 + receive_buffer[3]);
	}
	return (OP_OK);
}

int cpu_comres(int icdev, int len, UCHAR *send_cmd, UCHAR *receive_data) {
	UCHAR send_buffer[1024], receive_buffer[1024];
	int st, mytry;

	mytry = 0;
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
	send_buffer[9 + len] = cr_bcc(9 + len, send_buffer);

	repeat:
	/////
	HexDumpBuffer(stdout, send_buffer, 10 + len);

	st = send_com(icdev, 10 + len, send_buffer);
	if (st != OP_OK) {
		if (mytry++ < 2)
			goto repeat;
		return st;
	}

	memset(receive_buffer, 0xff, sizeof(receive_buffer));
	st = receive_com(icdev, receive_buffer);

	HexDumpBuffer(stdout, receive_buffer, receive_buffer[3] + 4);

	if (st != OP_OK) {
		if (mytry++ < 2)
			goto repeat;
		return st;
	}

	if (receive_buffer[1] != 0) {
		if (mytry++ < 2)
			goto repeat;
		return -receive_buffer[1];
	}

	memcpy(receive_data, receive_buffer + 4, receive_buffer[3]);

	return OP_OK;
}

int ic_delay(long mm) {

	clock_t start, end;

	start = clock();
	while (1) {
		end = clock();
		if ((end - start) > mm)
			break;
	}
	return 10;
}

int dv_beep(int icdev, int time) {

	unsigned char send_buffer[160];
	unsigned char receive_buffer[160];
	int st;

	if (time < 0)
		time = 2;

	if (time > 255)
		time = 255;

	send_buffer[0] = PC_HEAD;
	send_buffer[1] = CMD_BEEP;
	send_buffer[2] = 0x00;
	send_buffer[3] = 7;
	send_buffer[4] = COMUNAL;
	send_buffer[5] = 0x00;
	send_buffer[6] = 0x00;
	send_buffer[7] = 0x00;
	send_buffer[8] = 0x00;
	send_buffer[9] = 0x00;
	send_buffer[10] = (unsigned char) time;
	send_buffer[11] = cr_bcc(11, send_buffer);

	printf("ALARM: ");
	HexDumpBuffer(stdout, send_buffer, 12);
	st = send_com(icdev, 12, send_buffer);
	if (st != OP_OK)
		return (st);
	ic_delay((time / 5) * 1000);

	st = receive_com(icdev, receive_buffer);
	if (st != OP_OK)
		return (st);
	HexDumpBuffer(stdout, receive_buffer, 4 + receive_buffer[3]);

	return (-receive_buffer[1]);
}

