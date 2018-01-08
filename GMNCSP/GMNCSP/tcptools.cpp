#include "stdafx.h"

#pragma comment(lib,"ws2_32.lib")


static char IP[256];
static int PORT = 0;
static char CV[256];

void setCV(char *cv){
	memcpy(CV,cv,strlen(cv));
}


char * getCV(void){
	return CV;
}

void setIP(char *ip){
	memcpy(IP,ip,strlen(ip));
}

char *  getIP(void){
	return IP;
}

void setPORT(int port){
	PORT = port;
}

int getPORT(){
	return PORT;
}

int HsmSendToSocket(int sockfd, unsigned char *buffer, int *length, int timeout){
	int rc = -1;
	int len = -1;
	struct timeval stTimeOut;
	fd_set stSockReady;

	FD_ZERO(&stSockReady);
	FD_SET(sockfd,&stSockReady);

	if (timeout > 0){
		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;
		select(sockfd + 1, NULL, &stSockReady, NULL, &stTimeOut);
	}
	else{
		select(sockfd + 1, NULL, &stSockReady, NULL, NULL);
	}
	if (!(FD_ISSET(sockfd, &stSockReady))){
		return -1;
	}
	else{
		if ((len = send(sockfd,(char*)buffer,*length,0)) > 0){
			rc = 0;
		}
		if (*length != len){
			*length = rc = -1;
			return rc;
		}
	}
	*length = len;
	return (rc);
}

int comTcpSend(int sockfd, unsigned char *buffer, int *length, int timeout){
	return HsmSendToSocket(sockfd, buffer, length, timeout);
}

int HsmReceiveFromSocket(int sockfd, unsigned char *buffer,
	int *length, int timeout){
	int rc = -1;
	int recvlen = -1;
	struct timeval stTimeOut;
	fd_set stSockReady;

	FD_ZERO(&stSockReady);
	FD_SET(sockfd,&stSockReady);

	if (timeout > 0){
		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;
		select(sockfd+1,&stSockReady,NULL,NULL,&stTimeOut);
	}
	else{
		select(sockfd + 1, &stSockReady, NULL, NULL, NULL);
	}
	
	if (!(FD_ISSET(sockfd,&stSockReady))){
		return -1;
	}
	else{
		recvlen = recv(sockfd,(char*)buffer,*length,0);
		if (recvlen <= 0){
			rc = -1;
		}
		else{
			rc = 0;
		}
	}
	*length = recvlen;
	return (rc);
}

int comTcpReceive(int sockfd, unsigned char *buffer, int *length, int timeout){
	return HsmReceiveFromSocket(sockfd, buffer, length, timeout);
}

int comTcpCliSocketOpen(char *tcpaddr, int port, int timeout){
	int sockfd;
	struct sockaddr_in serv_addr;
	struct linger tcp_linger;
	int rc = 0;

	WSADATA wsadata;
	if (WSAStartup(0x202,&wsadata)){
		return (INVALID_SOCKET);
	}

	memset(&serv_addr,0x00,sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(tcpaddr);
	serv_addr.sin_port = htons((unsigned short)port);

	if ((sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0 ){
		rc = -1;
		return (rc);
	}

	rc = connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr_in));
	if (rc < 0){
		rc = -1;
		return (rc);
	}
	tcp_linger.l_onoff = 1;
	tcp_linger.l_linger = 0;
	setsockopt(sockfd,SOL_SOCKET,SO_LINGER,(char*)&tcp_linger,sizeof(struct linger));
	return (sockfd);
}

int InitHsmDevice(char *tcpaddr, int port, int timeout)
{
	return comTcpCliSocketOpen(tcpaddr, port, timeout);
}

int comTcpSvrSocketOpen(char *tcpaddr, int port){
	int sockfd = -1;
	int namelen;
	int value;
	struct sockaddr_in servaddr;
	WSADATA wsadata;

	if (WSAStartup(0x202,&wsadata)){
		return (INVALID_SOCKET);
	}
	if ((sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
		return (-1);
	}
	memset((char*)&servaddr, 0x00, sizeof(struct sockaddr_in));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons((unsigned short)port);

	value = 1;
	if ((setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(char *)&value,sizeof(value)))<0){
		return (-1);
	}
	if ((bind(sockfd,(struct sockaddr*)&servaddr,sizeof(struct sockaddr_in)))<0){
		return (-1);
	}
	namelen = sizeof(struct sockaddr_in);
	if (listen(sockfd,SOMAXCONN)<0){
		return (-1);
	}
	return sockfd;
}

int comTcpAccept(int sockfd, char *alCliaddr){
	struct sockaddr_in cliaddr;
	int consockfd = -1;
	struct linger tcp_linger;
	int namelen;
	int value;
	
	namelen = sizeof(struct sockaddr_in);
	memset((char*)&cliaddr,0x00,namelen);
	if ((consockfd = accept(sockfd,(struct sockaddr*)&cliaddr,&namelen))<0){
		if (errno != EINTR)
			return (-1);
	}
	tcp_linger.l_onoff = 1;
	tcp_linger.l_linger = 0;
	setsockopt(consockfd,SOL_SOCKET,SO_LINGER,(char *)&tcp_linger,sizeof(struct linger));

	value = 8192;
	setsockopt(consockfd,SOL_SOCKET,SO_SNDBUF,(char*)&value,sizeof(value));
	setsockopt(consockfd,SOL_SOCKET,SO_RCVBUF,(char*)&value,sizeof(value));
	return (consockfd);
}

int comTcpSocketClose(int sockfd){
	int rc = 0;
	shutdown(sockfd,2);
	if ((rc = closesocket(sockfd)) < 0){
		return (-1);
	}
	WSACleanup();
	return (rc);
}


int CloseHsmDevice(int comid)
{
	return comTcpSocketClose(comid);
}

int HsmCmdRun(int comid, int msghdlen, char * msghd, char *cmd, int cmdlen, char *rsp, int *rsplen){
	UCHAR *p;
	UCHAR cmd_buf[MAX_MSGDATA + 1];
	UCHAR send_buf[MAX_MSGDATA+1];
	UCHAR ret_buf[MAX_MSGDATA+1];
	int cmd_len = 0;
	int ret_len = 0;
	int rc;

	p = cmd_buf;
	p = short2hex((USHORT)cmdlen,p);

	memcpy(p,cmd,cmdlen);
	p += cmdlen;
	*p = 0;
	cmd_len = p - cmd_buf;
	memcpy(send_buf,cmd_buf,cmd_len);
	
	LogEntry("SEND:", cmd, sizeof(cmd), 1);
	
	rc = comTcpSend(comid,send_buf,&cmd_len,SEND_TIMEOUT);
	if (rc < 0){
		return (HSM_ERR_SEND);
	}
	ret_len = sizeof(ret_buf);
	rc = comTcpReceive(comid,ret_buf,&ret_len,RECV_TIMEOUT);
	if (rc < 0){
		return (HSM_ERR_RECV);
	}
	
	*(ret_buf + ret_len) = 0;
	*rsplen = (ret_len - (2+msghdlen+2+2));
	*(rsp + *rsplen) = 0;
	if (ret_len != (int)(hex2short(ret_buf) + 2)){
		return (HSM_ERR_LENGTH);
	}
	
	if (msghdlen){
		if (memcmp(cmd_buf + 2, ret_buf + 2, msghdlen))  return(HSM_ERR_MSGHD);
	}
	if ((cmd_buf[2 + msghdlen + 1] + 1) != ret_buf[2 + msghdlen + 1])	return(HSM_ERR_CMDRSP);

	LogEntry("RECV:", (char*)(ret_buf+2), 0, 1);
	if (!memcmp(&ret_buf[2 + msghdlen + 2], "00", 2)){
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




