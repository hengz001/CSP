#include "mgrSvr.h"

int OpenConsolePort(void) {

	int fd;
	async_port_t *port = &phsmShm->hsmcfg.rCc;

	int selBaud = GetCfgBaudRate(port->port_parm.baudrate);
	int selWord = GetCfgWordFormat(&port->port_parm.parm);

	if ((selBaud >= 6 && selBaud <= 10) && selWord == 4) {
		fd = OpenTtyPort(CONSOLE_PORT, port);
	} else {
		port->port_parm.baudrate = B19200;
		port->port_parm.parm.csize = CS8;
		port->port_parm.parm.parity = 0;
		port->port_parm.parm.stopbit = 0;
		fd = OpenTtyPort(CONSOLE_PORT, port);
	}
	return (fd);
}

int OpenTtyPort(char *portname, async_port_t *port) {
	port_parm_t *port_parm = &port->port_parm;
	struct termios oldtio, newtio;
	int fd;
	int rc = 0;
	/*
	 System Call to get the global handle of the serial port.
	 */
	fd = open(portname, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		port->fd = -1;
		//perror(devname);
		return -1;
	}
	rc = tcgetattr(fd, &oldtio); /* save the old settings */
	bzero(&newtio, sizeof(newtio));

	//attach to the shared memory to get Baudrate
	//???????????????????????????????????????????? 030129
	///////////////////////////////////////////////

	/*
	 BAUDRATE: 脡猫露篓 bps 碌脛脣脵露脠. 脛茫脪虏驴脡脪脭脫脙 cfsetispeed 录掳 cfsetospeed
	 脌麓脡猫露篓.
	 CRTSCTS : 脢盲鲁枚脳脢脕脧碌脛脫虏脤氓脕梅脕驴驴脴脰脝 (脰禄脛脺脭脷戮脽脥锚脮没脧脽脗路碌脛脌脗脧脽脧脗鹿陇脳梅
	 虏脦驴录 Serial-HOWTO 碌脷脝脽陆脷)
	 CS8     : 8n1 (8 脦禄脭陋, 虏禄脳枚脥卢脦禄脭陋录矛虏茅,1 赂枚脰脮脰鹿脦禄脭陋)
	 CLOCAL  : 卤戮碌脴脕卢脧脽, 虏禄戮脽脢媒戮脻禄煤驴脴脰脝鹿娄脛脺
	 CREAD   : 脰脗脛脺陆脫脢脮脳脰脭陋
	 */
	//newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;
	newtio.c_cflag = port_parm->baudrate | port_parm->parm.csize
			| port_parm->parm.parity | port_parm->parm.stopbit;

	newtio.c_cflag |= CRTSCTS | CLOCAL | CREAD;
	/*
	 IGNPAR  : 潞枚脗脭戮颅脥卢脦禄脭陋录矛虏茅谩谩, 麓铆脦贸碌脛脦禄脭陋脳茅
	 ICRNL   : 卤脠 CR 露脭脫娄鲁脡 NL (路帽脭貌碌卤脢盲脠毛脩露潞脜脫脨 CR 脢卤虏禄禄谩脰脮脰鹿脢盲脠毛)
	 脭脷虏禄脠禄掳脩脳掳脰脙脡猫露篓鲁脡 raw 脛拢脢陆(脙禄脫脨脝盲脣眉碌脛脢盲脠毛麓娄脌铆)
	 */
	newtio.c_iflag = IGNPAR | ICRNL;
	//   newtio.c_iflag = IGNPAR | INLCR;

	/*
	 Raw 脛拢脢陆脢盲鲁枚.
	 */
	newtio.c_oflag = OCRNL;
	// newtio.c_oflag = ONLCR;

	/*
	 ICANON  : 脰脗脛脺卤锚脳录脢盲脠毛, 脢鹿脣霉脫脨禄脴脫娄禄煤脛脺脥拢脫脙, 虏垄虏禄脣脥鲁枚脨脜潞脜脪脭陆脨脫脙鲁脤脢陆
	 */
	//newtio.c_lflag = ICANON | ECHO;
	newtio.c_lflag = ICANON | ECHO;

	/*
	 鲁玫脢录禄炉脣霉脫脨碌脛驴脴脰脝脤脴脨脭
	 脭陇脡猫脰碌驴脡脪脭脭脷 /usr/include/termios.h 脮脪碌陆, 脭脷脳垄陆芒脰脨脪虏脫脨,
	 碌芦脦脪脙脟脭脷脮芒虏禄脨猫脪陋驴麓脣眉脙脟
	 */
	newtio.c_cc[VINTR] = 0; /* Ctrl-c */
	newtio.c_cc[VQUIT] = 0; /* Ctrl-\ */
	newtio.c_cc[VERASE] = 0; /* del */
	newtio.c_cc[VKILL] = 0; /* @ */
	newtio.c_cc[VEOF] = 4; /* Ctrl-d */
	newtio.c_cc[VTIME] = 0; /* 虏禄脢鹿脫脙路脰赂卯脳脰脭陋脳茅碌脛录脝脢卤脝梅 */
	newtio.c_cc[VMIN] = 1; /* 脭脷露脕脠隆碌陆 1 赂枚脳脰脭陋脟掳脧脠脥拢脰鹿 */
	newtio.c_cc[VSWTC] = 0; /* '\0' */
	newtio.c_cc[VSTART] = 0; /* Ctrl-q */
	newtio.c_cc[VSTOP] = 0; /* Ctrl-s */
	newtio.c_cc[VSUSP] = 0; /* Ctrl-z */
	newtio.c_cc[VEOL] = 0; /* '\0' */
	newtio.c_cc[VREPRINT] = 0; /* Ctrl-r */
	newtio.c_cc[VDISCARD] = 0; /* Ctrl-u */
	newtio.c_cc[VWERASE] = 0; /* Ctrl-w */
	newtio.c_cc[VLNEXT] = 0; /* Ctrl-v */
	newtio.c_cc[VEOL2] = 0; /* '\0' */

	/* Set output speed */
	rc |= cfsetospeed(&newtio, port_parm->baudrate);

	/* Check output speed */
	if (!rc) {
		if (port_parm->baudrate != cfgetospeed(&newtio)) {
			port->fd = -1;
			return (-1);
		}
	}

	/* Set input speed */
	rc |= cfsetispeed(&newtio, port_parm->baudrate);

	/* Check input speed */
	if (!rc) {
		if (port_parm->baudrate != cfgetispeed(&newtio)) {
			port->fd = -1;
			return (-1);
		}
	}
	/*
	 * Now clean the modem line and activate the settings for modem
	 */
	rc |= tcflush(fd, TCIFLUSH);
	rc |= tcsetattr(fd, TCSANOW, &newtio);

	if (rc) {
		port->fd = -1;
		return (-1);
	}

	/* Save file handler in structure */
	port->fd = fd;

	return fd;

}
