#include "mgrSvr.h"

int WriteNewLine(int fd) {
	return write(fd, "\n\r", 2);
}

int _WriteLine(int fd, char *local, char *def, int mode) {
	int len;

	if (mode) {
		WriteNewLine(fd);
	}

	if (HsmGetLanguage()) {
		len = strlen(local);
		write(fd, local, len);
	} else {
		len = strlen(def);
		write(fd, def, len);
	}

	return len;
}

int WriteLine(int fd, char *local, char *def) {
	return _WriteLine(fd, local, def, 1);
}

int setterm(int fd, struct termios *Term, int Flag) {
	struct termios newtio;
	switch (Flag) {
	case 0:
		/* 储存目前的序列埠设定 */
		if (tcgetattr(fd, Term) < 0) {
			return (-1);
		}
		/* 储存目前的序列埠设定 */
		if (tcgetattr(fd, &newtio) < 0) {
			return (-1);
		}
		newtio.c_lflag &= (IXON | IXOFF);
		newtio.c_cc[VMIN] = 1;
		newtio.c_cc[VTIME] = 0;
		tcflush(fd, TCIFLUSH);
		if (tcsetattr(fd, TCSANOW, &newtio) < 0) {
			return (-1);
		}
		return 0;
	case 1:
		if (tcsetattr(fd, TCSANOW, Term) < 0) {
			return -1;
		}
		return 0;
	default:
		return -1;
	}
}

int getpasswd(int fd, char *locmsg, char *defmsg, char *passwd, int echo) {
	struct termios OldTerm;
	char Buf[1024];
	char ch;
	int i, rc;

	if (locmsg != NULL || defmsg != NULL) {

		WriteLine(fd, locmsg, defmsg);
	}

	memset(Buf, 0, sizeof(Buf));
	if ((setterm(fd, &OldTerm, 0)) < 0) {
		return -1;
	}
	i = 0;
	while (1) {
		int nbytes;

		ioctl(fd, FIONREAD, &nbytes);
		usleep(100);

		if (nbytes) {

			if (read(fd, &ch, 1) != 1) {
				continue;
			}
			switch (ch) {
			case '\n':
				Buf[i] = 0;
				rc = i;
				goto err;
			case '^':
				echo = 0;
				break;
			case 0x08: //Backspace
				i--;
				if (i >= 0) {
					write(fd, "\b", 1);
					write(fd, " ", 1);
					write(fd, "\b", 1);
				} else {
					i = 0;
				}
				continue;
			case 0x7F: //DEL
				Buf[0] = 0;
				rc = -1;
				goto err;
			default:
				if (isprint(ch)) {
					Buf[i++] = ch;
				} else {
					Buf[0] = 0;
					rc = -5;
					goto err;
				}

				if (echo == ECHO_ON) {
					write(fd, &ch, 1);
				} else if (echo == ECHO_OFF) {
					write(fd, "*", 1);
				}
			}
		}
	}
	err:

	if (setterm(fd, &OldTerm, 1) < 0) {
		return -2;
	}
	if (strlen(Buf)) {
		strcpy(passwd, Buf);
	}

	memset(Buf, 0, sizeof(Buf));
	return rc;
}

void trim_r_space(char *string) {
	char *ptr = string + strlen(string);

	--ptr;
	for (; *ptr == '\n' || isspace(*ptr); ptr--) {
		if (ptr >= string) {
			*ptr = 0;
		} else {
			break;
		}
	}
}

int _ReadLine(int fd, char *buf, int len, int mode) {
	int bytes;

	bytes = getpasswd(fd, NULL, NULL, buf, ECHO_ON);

	if (bytes > 0) {
		buf[bytes] = 0;

		trim_r_space(buf);

		if (mode) {
			strupper(buf);
		}

		return strlen(buf);
	} else if (bytes == 0) {
		buf[bytes] = 0;
		return 0;
	}

	return (-1);
}

int ReadLine(int fd, char *buf, int len) {
	return _ReadLine(fd, buf, len, 1);
}

int ReadPromptMessage(int fd,char *buf)
{
	int bytes;

	bytes = getpasswd(fd,NULL,NULL,buf,ECHO_NOECHO);
	WriteNewLine(fd);

	if(bytes>0)
	{
		buf[bytes] = 0;
		trim_r_space(buf);
		strupper(buf);
		return strlen(buf);
	}
	else if(bytes == 0){
		buf[bytes] = 0;
		return 0;
	}

	return (-1);
}

void message(int fd, char *buf, const char *format,...)
{
	va_list args;

	va_start(args,format);
	vsprintf(buf,format,args);
	WriteNewLine(fd);
	write(fd,buf,strlen(buf));
	va_end(args);
}

/*** Make sure the string is the correct char set ***/
int ismystring(char *str,int mode)
{
	char *p=str;
	int  isiwanted = 1;

	for(;;)
	{
		switch(mode)
		{
			case HEX_CHAR:
				isiwanted=isiwanted&&isxdigit((int)(*p));
				/***printf("HEX_CHAR![%d]\n",isiwanted);***/
				break;

			case DEC_CHAR:
				isiwanted=isiwanted&&isdigit((int)(*p));
				/***printf("DEC_CHAR![%d]\n",isiwanted);***/
				break;

			/*** If don't care the character set ***/
			default:
				isiwanted=isiwanted&&isascii((int)(*p));
				/***printf("ANY_CHAR![%d]\n",isiwanted);***/
				break;
		}

		p++;

		if(!isiwanted)	break;
		if(*p==0)	break;

	}

	return (isiwanted);
}

/*** Get A String from Input Device ***/
int enterastring(int fd, char *locmsg, char *defmsg, char *key, int *len, int mode, int echo)
{

	int  first = 1;
	int  length;
	int  rc;	/* Internal return value */

	do {
		if(first)
		{
			/*** Enter a triple length DES key ***/
			rc = getpasswd(fd, locmsg, defmsg, key, echo);
		}
		else
		{
			rc = getpasswd(fd,"输入非法! 请重新输入: ","Invalid! Enter again: ", key, echo);
		}

		if(rc<=0) return rc;

		first = 0;

		length = strlen(key);

		if(mode!=ANY_CHAR)
		{
			/*** Strip of white spaces in the key string ***/
			StripOffWhiteSpaces(key, length);

			/*** Calculate the length of the key just entered ***/
			length = strlen(key);

			/* If the input data length is not the times of 16 */
			//if(*len==0||*len%16)	*len = ((length+15) / 16 ) * 16;
			// GMN12222003Ro deleted
			//strupper(key);
		}

	} while(!ismystring(key,mode) || (mode!=ANY_CHAR&&length!=*len));

	/* 05262003Ro */
	*len = length;

	return 0;
}

