#include "stdafx.h"

#define CK_Win32
#ifdef CK_Win32

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>
#include <stdlib.h> 
#include <windows.h>
#include <winbase.h>
#include <time.h>
#include <sys/timeb.h>
#include <memory.h>

#include "hsm_com.h"
#include "hsm_tcpsub.h"
#include "hsmcmd.h"

#pragma comment(lib,"ws2_32")

int HsmSendToSocket(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	int	rc = -1;
	int	len = -1;
	struct 	timeval stTimeOut;
	fd_set	stSockReady;

	FD_ZERO(&stSockReady);
	FD_SET(sockfd, &stSockReady);


	if (timeout > 0)
	{
		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;

		select(sockfd + 1, NULL, &stSockReady, NULL, &stTimeOut);
	}
	else
	{
		select(sockfd + 1, NULL, &stSockReady, NULL, NULL);
	}

	if (!(FD_ISSET(sockfd, &stSockReady)))
	{
		rc = -1;

	}
	else
	{

		if ((len = send(sockfd, (char*)buffer, *length, 0)) > 0)
		{
			rc = 0;
		}

		if (*length != len)
		{
			*length = rc = -1;
			return rc;
		}

	}

	*length = len;

	return (rc);

}

int comTcpSend(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	return HsmSendToSocket(sockfd, buffer, length, timeout);
}


int HsmReceiveFromSocket(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	int	rc = -1;
	int	rcvlen = -1;
	struct 	timeval stTimeOut;
	fd_set	stSockReady;

	FD_ZERO(&stSockReady);
	FD_SET(sockfd, &stSockReady);


	if (timeout > 0)
	{
		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;
		select(sockfd + 1, &stSockReady, NULL, NULL, &stTimeOut);

	}
	else
	{
		select(sockfd + 1, &stSockReady, NULL, NULL, NULL);
	}

	if (!(FD_ISSET(sockfd, &stSockReady)))
	{
		rc = -1;
	}
	else
	{
		rcvlen = recv(sockfd, (char*)buffer, *length, 0);

		if (rcvlen <= 0)
		{
			rc = -1;
		}
		else
		{
			rc = 0;
		}
	}

	*length = rcvlen;

	return (rc);

}

int comTcpReceive(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	return HsmReceiveFromSocket(sockfd, buffer, length, timeout);
}

int comTcpCliSocketOpen(char *tcpaddr, int port, int timeout)
{
	int	sockfd;

	struct sockaddr_in serv_addr;
	struct linger tcp_linger;
	int    rc = 0;


	WSADATA  wsadata;

	if (WSAStartup(0x202, &wsadata))
	{
		return(INVALID_SOCKET);
	}


	memset(&serv_addr, 0x00, sizeof(struct sockaddr_in));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(tcpaddr);
	serv_addr.sin_port = htons((unsigned short)port);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		rc = -1;
		return(rc);
	}

	rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));


	if (rc < 0)
	{
		rc = -1;
		return(rc);
	}

	tcp_linger.l_onoff = 1; /* Linger On */
	tcp_linger.l_linger = 0; /* 0 seconds */
	setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (char *)&tcp_linger, sizeof(struct linger));

	return (sockfd);
}

int comTcpSvrSocketOpen(char *tcpaddr, int port)
{
	int	sockfd = -1;

	int	namelen;

	int	value;

	struct sockaddr_in servaddr;

	WSADATA  wsadata;

	if (WSAStartup(0x202, &wsadata))
	{
		return(INVALID_SOCKET);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		return(-1);
	}

	memset((char *)&servaddr, 0x00, sizeof(struct sockaddr_in));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons((unsigned short)port);

	value = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&value, sizeof(value)) < 0)
	{
		return(-1);
	}


	if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(struct sockaddr_in)) < 0)
	{
		return(-1);
	}

	namelen = sizeof(struct sockaddr_in);

	if (listen(sockfd, SOMAXCONN) < 0)
	{
		return(-1);
	}

	return sockfd;

}

int comTcpAccept(int sockfd, char *alCliaddr)
{

	struct	sockaddr_in cliaddr;

	int	consockfd = -1;
	struct	linger tcp_linger;

	int	namelen;
	int	value;

	namelen = sizeof(struct sockaddr_in);

	memset((char *)&cliaddr, 0x00, namelen);

	if ((consockfd = accept(sockfd, (struct sockaddr*)&cliaddr, &namelen)) < 0)
	{
		if (errno != EINTR) return(-1);
	}

	tcp_linger.l_onoff = 1;
	tcp_linger.l_linger = 0;
	setsockopt(consockfd, SOL_SOCKET, SO_LINGER, (char *)&tcp_linger, sizeof(struct linger));

	value = 8192;
	setsockopt(consockfd, SOL_SOCKET, SO_SNDBUF, (char *)&value, sizeof(value));
	setsockopt(consockfd, SOL_SOCKET, SO_RCVBUF, (char *)&value, sizeof(value));

	return (consockfd);
}

int comTcpSocketClose(int sockfd)
{
	int  rc = 0;

	shutdown(sockfd, 2);

	if ((rc = closesocket(sockfd)) < 0)
	{
		rc = -1;
	}

	WSACleanup();

	return (rc);
}


int InitHsmDevice(char *tcpaddr, int port, int timeout)
{
	return comTcpCliSocketOpen(tcpaddr, port, timeout);
}


int CloseHsmDevice(int comid)
{
	return comTcpSocketClose(comid);
}


int HsmCmdRun(int comid, int msghdlen, char * msghd, char *cmd, int cmdlen, char *rsp, int *rsplen)
{
	unsigned char   cmd_buf[MAX_MSGDATA + 1], *p;
	unsigned char   send_buf[MAX_MSGDATA + 1];
	unsigned char   ret_buf[MAX_MSGDATA + 1];


	int  cmd_len = 0, ret_len = 0, rc;

	/*
	// RACAL CMD = 2 Bytes Length + N bytes Message Header +
	// 2 bytes Command Code + CMD Messge
	*/
	p = cmd_buf;
	printf("CMD:%s\n",cmd);
	/*
	// 2 Bytes Length
	*/
	p = short2hex((unsigned short)cmdlen, p);

	memcpy(p, cmd, cmdlen);
	p += cmdlen;

	*p = 0;
	cmd_len = p - cmd_buf;

	memcpy(send_buf, cmd_buf, cmd_len);

	rc = comTcpSend(comid, send_buf, &cmd_len, SEND_TIMEOUT);

	if (rc < 0) return(HSM_ERR_SEND);


	ret_len = sizeof(ret_buf);

	rc = comTcpReceive(comid, ret_buf, &ret_len, RECV_TIMEOUT);

	if (rc < 0)	return(HSM_ERR_RECV);



	*(ret_buf + ret_len) = 0;


	/*
	// Response: 2 Bytes Length + N bytes Message Header +
	// 2 bytes Command Response + 2 Bytes Error Code + Response Message
	*/

	*rsplen = (ret_len - (2 + msghdlen + 2 + 2));

	*(rsp + *rsplen) = 0;

	/*
	// Check response length, if invalid ...
	*/
	if (ret_len != (int)(hex2short(ret_buf) + 2 /*bytes length*/))  return (HSM_ERR_LENGTH);

	/*
	// Check message header, if consistent ...
	*/

	/* modified by jimmy on 050705112*/
	if (msghdlen)
		if (memcmp(cmd_buf + 2, ret_buf + 2, msghdlen))  return(HSM_ERR_MSGHD);

	/*
	// Check Command Response, if invalid ...
	*/
	if ((cmd_buf[2 + msghdlen + 1] + 1) != ret_buf[2 + msghdlen + 1])	return(HSM_ERR_CMDRSP);

	/*
	// Check response code, if no error ...
	*/
	if (!memcmp(&ret_buf[2 + msghdlen + 2], "00", 2)) {

		memcpy(rsp, (unsigned char *)&ret_buf[2 + msghdlen + 2 + 2], *rsplen);
		return (0);
	}
	else
	{
		rc = (ret_buf[2 + msghdlen + 2] - 48) * 10;
		rc = rc + (ret_buf[2 + msghdlen + 3] - 48);
		rc = 0 - rc;
		//return (HSM_ERR_RSPERR);
		return (rc);
	}
}


#else

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <setjmp.h>

#include <stdlib.h>
#include <dirent.h>

#include "hsmcmd.h"
#include "hsmdefs.h"
#include "hsm_tcpsub.h"


/*
#define __DEBUG__
*/


/****************************************************************

 Function:   HsmSendToSocket

 Invocation: rc =  HsmSendToSocket(sockfd, buffer, &length);

 Author: Robert Shen 			Date: July 18, 1999.

 Description: Send data over current TCP/IP connection

 Arguments:

	Input:
		sockfd	- A integer to the current socket file descriptor
		buffer	- A pointer to the data buffer
		length	- A integer pointer to the max. buffer length

	Output:
		length - Returns the real data length sent

	Return Value:
		0		- No error
		-1		- Failed to send data on the current TCP/IP connection

Revision:
	20040310 - Rewrite the function by Forest Leo

******************************************************************/

int HsmSendToSocket(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	int	rc = -1;
	int	len = -1;
	struct 	timeval stTimeOut;
	fd_set	stSockReady;

	FD_ZERO(&stSockReady);
	FD_SET(sockfd, &stSockReady);


	if (timeout > 0) {

		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;

		select(sockfd + 1, NULL, &stSockReady, NULL, &stTimeOut);

	}
	else select(sockfd + 1, NULL, &stSockReady, NULL, NULL);

	if (!(FD_ISSET(sockfd, &stSockReady)))
	{
		rc = -1;

	}
	else {

		if ((len = write(sockfd, buffer, *length)) > 0) rc = 0;

		if (*length != len)	/* 20010320Ro */
		{
			*length = rc = -1;

			return rc;
		}

	}

	*length = len;

	return (rc);

}

int comTcpSend(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	return HsmSendToSocket(sockfd, buffer, length, timeout);
}

/****************************************************************

 Function:  HsmReceiveFromSocket

 Invocation: rc =  HsmReceiveFromSocket(sockfd, buffer, &length);

 Author: Robert Shen 			Date: July 18, 1999.

 Description: Receive data over current TCP/IP connection

 Arguments:

	Input:
		sockfd	- A integer to the current socket file descriptor
		buffer	- A pointer to the data buffer
		length	- A integer pointer to the max. buffer length

	Output:
		length - Returns the real received data length

	Return Value:
		0		- No error
		-1		- Failed to receive data on the current TCP/IP connection

******************************************************************/

int HsmReceiveFromSocket(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	int	rc = -1;
	int	rcvlen = -1;
	struct 	timeval stTimeOut;
	fd_set	stSockReady;

	FD_ZERO(&stSockReady);
	FD_SET(sockfd, &stSockReady);


	if (timeout > 0) {

		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;

		select(sockfd + 1, &stSockReady, NULL, NULL, &stTimeOut);

	}
	else select(sockfd + 1, &stSockReady, NULL, NULL, NULL);

	if (!(FD_ISSET(sockfd, &stSockReady)))
	{
		rc = -1;

	}
	else {

		rcvlen = read(sockfd, buffer, *length);

		if (rcvlen <= 0) {

			rc = -1;

		}
		else {

			rc = 0;
		}
	}

	*length = rcvlen;

	return (rc);

}

int comTcpReceive(int sockfd, unsigned char *buffer, int *length, int timeout)
{
	return HsmReceiveFromSocket(sockfd, buffer, length, timeout);
}



/****************************************************************

 Function:	comTcpCliSocketOpen

 Invocation: rc =  comTcpCliSocketOpen(tcpaddr, port);

 Author: Robert Shen 			Date: July 18, 1999.

 Description: Start a TCP/IP client connection

 Arguments:

	Input:
		tcpaddress - A pointer to TCP/IP server address(e.g. 192.1.1.233)
		port	- A integer to specify a port number

	Output:

	Return Value:
		sockfd		- No error, return the socket file descriptor
		-1		- Failed to start a TCP/IP client connection

Revision:
	20040310 - Rewrite the function by Forest Leo
******************************************************************/

int comTcpCliSocketOpen(char *tcpaddr, int port, int timeout)
{
	int	sockfd, flags, len;

	struct sockaddr_in serv_addr;
	struct linger tcp_linger;
	int    rc = 0;

	struct  timeval stTimeOut;

	fd_set rset;
	fd_set wset;
	fd_set eset;


	bzero((char *)&serv_addr, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(tcpaddr);
	serv_addr.sin_port = htons(port);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		rc = -1;
		return(rc);
	}

	if (timeout > 0) {


		flags = fcntl(sockfd, F_GETFL, 0);

		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);


		rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));


		if (rc < 0) {

			if (errno == EINPROGRESS) {

				stTimeOut.tv_sec = timeout;
				stTimeOut.tv_usec = 0;

				FD_ZERO(&rset);
				FD_ZERO(&eset);
				FD_SET(sockfd, &rset);
				FD_SET(sockfd, &eset);

				wset = rset;

				if ((rc = select(sockfd + 1, &rset, &wset, &eset, &stTimeOut)) == 0) {


					fcntl(sockfd, F_SETFL, flags);
					return -1; /* TIMEDOUT */

				}
				else if ((FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset))) {

					rc = 0;

					len = sizeof(rc);


					if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &rc, &len) < 0) {

						fcntl(sockfd, F_SETFL, flags);
						return -1;
					}

					if (rc) {

						fcntl(sockfd, F_SETFL, flags);
						return -1;
					}

				}
				else {

					fcntl(sockfd, F_SETFL, flags);
					return -1;
				}
			}
		}
		else {
			fcntl(sockfd, F_SETFL, flags);
		}

	}
	else {

		rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));

	}

	if (rc < 0) {

		rc = -1;
		return(rc);
	}

	tcp_linger.l_onoff = 1; /* Linger On */
	tcp_linger.l_linger = 0; /* 0 seconds */
	setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &tcp_linger, sizeof(struct linger));

	return (sockfd);
}


/****************************************************************

 Function:   comTcpSvrSocketOpen

 Invocation: rc =  comTcpSvrSocketOpen(tcpaddr, port);

 Author: Robert Shen 			Date: July 18, 1999.

 Description: Start an asynchronous TCP/IP server deamon

 Arguments:

	Input:
		tcpaddr	- A pointer to the received message IP address
		port	- A integer to specify a port number

	Output:

	Return Value:
		sockfd		- No error, return the socket file descriptor
		-1		- Failed to start a TCP/IP server

Revision:
	20040310 - Rewrite the function by Forest Leo

******************************************************************/

int comTcpSvrSocketOpen(char *tcpaddr, int port)
{
	int	sockfd = -1;

	int	namelen;

	int	value;

	struct sockaddr_in servaddr; /* the rest is null */


	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
#ifdef	__DEBUG__
		DebugMessageLog("Open Tcp/Ip socket failure!");
#endif
		return(-1);
	}

	memset((char *)&servaddr, 0x00, sizeof(struct sockaddr_in));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

#ifdef	__DEBUG__
	DebugMessageLog("TCP Listen_Port: %ld", port);
#endif

	value = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
		return(-1);
	}


	if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(struct sockaddr_in)) < 0)
	{
#ifdef	__DEBUG__
		DebugMessageLog("TCP/IP bind error!");
#endif
		return(-1);
	}

	namelen = sizeof(struct sockaddr_in);

	if (listen(sockfd, SOMAXCONN) < 0)
	{
#ifdef	__DEBUG__
		DebugMessageLog("TCP/IP listen error!");
#endif
		return(-1);
	}

	return sockfd;

}


/****************************************************************

 Function:   comTcpAccept

 Invocation: rc =  comTcpAccept(sockfd);

 Author: Robert Shen 			Date: July 18, 1999.

 Description: Start an asynchronous TCP/IP server deamon

 Arguments:

	Input:
		sockfd	- A integer pointer to a socket file descriptor

	Output:

	Return Value:
		newsockfd	- No error, Returns the real socket file descriptor
		-1		- Any error

Revision:
	20040310 - Rewrite the function by Forest Leo

******************************************************************/

int comTcpAccept(int sockfd, char *alCliaddr)
{

	struct	sockaddr_in cliaddr;   /* the rest is null */

	int	consockfd = -1;
	struct	linger tcp_linger;

	int	namelen;
	int	value;

	namelen = sizeof(struct sockaddr_in);

	memset((char *)&cliaddr, 0x00, namelen);

	if ((consockfd = accept(sockfd, (struct sockaddr*)&cliaddr, &namelen)) < 0)
	{
#ifdef	__DEBUG__
		DebugMessageLog("TCP/IP accept error!");
#endif
		if (errno != EINTR) return(-1);
	}

	tcp_linger.l_onoff = 1;
	tcp_linger.l_linger = 0;
	setsockopt(consockfd, SOL_SOCKET, SO_LINGER, &tcp_linger, sizeof(struct linger));


	value = 8192;
	setsockopt(consockfd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value));
	setsockopt(consockfd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));

	/*** get client ip ***/
	sprintf(alCliaddr, "%s", inet_ntoa(cliaddr.sin_addr));

	return (consockfd);
}


/****************************************************************

 Function:  comTcpClose

 Invocation: rc =  comTcpClose(sockfd);

 Author: Robert Shen                    Date: July 18, 1999.

 Description: Tcp/IP Common Socket Close Fnction

 Arguments:

		Input:
				sockfd  - A integer to the current socket file descriptor

		Output: Noe

		Return Value:
				0               - No error
				-1              - Failed to close the TCP/IP socket file descriptor

Revision:
	20040310 - Rewrite the function by Forest Leo

******************************************************************/

int comTcpSocketClose(int sockfd)
{
	int             rc = 0;

	shutdown(sockfd, 2);

	if ((rc = close(sockfd)) < 0)
	{
		rc = -1;
	}
	return (rc);
}


int InitHsmDevice(char *tcpaddr, int port, int timeout)
{
	return comTcpCliSocketOpen(tcpaddr, port, timeout);
}

int CloseHsmDevice(int comid)
{
	return comTcpSocketClose(comid);
}

int HsmCmdRun(int comid, int msghdlen, char * msghd, char *cmd, int cmdlen, char *rsp, int *rsplen)
{
	unsigned char   cmd_buf[MAX_MSGDATA + 1], *p;
	unsigned char   send_buf[MAX_MSGDATA + 1];
	unsigned char   ret_buf[MAX_MSGDATA + 1];

	int  cmd_len = 0, ret_len = 0, rc;

	/*
	// RACAL CMD = 2 Bytes Length + N bytes Message Header +
	// 2 bytes Command Code + CMD Messge
*/

	p = cmd_buf;

	/*
	// 2 Bytes Length
	*/

	p = short2hex(cmdlen, p);

	memcpy(p, cmd, cmdlen);

	p += cmdlen;

	*p = 0;

	cmd_len = p - cmd_buf;

	memcpy(send_buf, cmd_buf, cmd_len);


	rc = comTcpSend(comid, send_buf, &cmd_len, SEND_TIMEOUT);

	if (rc < 0) return (HSM_ERR_SEND);


	ret_len = sizeof(ret_buf);

	if ((rc = comTcpReceive(comid, ret_buf, &ret_len, RECV_TIMEOUT)) < 0)	return (HSM_ERR_RECV);


	*(ret_buf + ret_len) = 0;


	/*
	// Response: 2 Bytes Length + N bytes Message Header +
	// 2 bytes Command Response + 2 Bytes Error Code + Response Message
	*/

	*rsplen = (ret_len - (2 + msghdlen + 2 + 2));

	*(rsp + *rsplen) = 0;

	/*
	// Check response length, if invalid ...
	*/

	if (ret_len != (int)(hex2short(ret_buf) + 2 /*bytes length*/))  return (HSM_ERR_LENGTH);

	/*
	// Check message header, if consistent ...
	*/

	/* modified by jimmy on 050705112*/
	if (msghdlen)
		if (memcmp(cmd_buf + 2, ret_buf + 2, msghdlen))  return (HSM_ERR_MSGHD);

	/*
		// Check Command Response, if invalid ...
		*/
	if ((cmd_buf[2 + msghdlen + 1] + 1) != ret_buf[2 + msghdlen + 1])  return (HSM_ERR_CMDRSP);

	/*
	// Check response code, if no error ...
	*/
	if (!memcmp(&ret_buf[2 + msghdlen + 2], "00", 2))
	{

		memcpy(rsp, (unsigned char *)&ret_buf[2 + msghdlen + 2 + 2], *rsplen);
		return (0);
	}
	else
	{
		rc = (ret_buf[2 + msghdlen + 2] - 48) * 10;
		rc = rc + (ret_buf[2 + msghdlen + 3] - 48);
		rc = 0 - rc;
		/*return (HSM_ERR_RSPERR);
*/        	return (rc);
	}
}



#endif


