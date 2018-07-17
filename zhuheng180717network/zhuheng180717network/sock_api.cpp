#include "stdafx.h"
#include "sock_api.h"


int getSocket()
{
	int rc = 0;
	WSADATA wsd;
	SOCKET sock;
	char FAR name[256];
	struct hostent FAR * pHost = NULL;
	SOCKADDR_IN sa;
	unsigned int optval = 1;
	DWORD dwByteRet;


	WSAStartup(MAKEWORD(2,1),&wsd);
	
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP))==SOCKET_ERROR) 
	{
		rc = -1;
		goto end;
	}

	gethostname(name,sizeof(name));
	if (NULL == (pHost = gethostbyname(name))) 
	{
		rc = -2;
		goto end;
	}
	sa.sin_family = AF_INET;
	sa.sin_port = htons(6000);
	memcpy(&sa.sin_addr.S_un.S_addr,pHost->h_addr_list[0],pHost->h_length);
	
	if ((bind(sock,(SOCKADDR *)&sa,sizeof(sa))) != 0) 
	{
		rc = -3;
		goto end;
	}

	WSAIoctl(sock,_WSAIOW(IOC_VENDOR,1),&optval,sizeof(optval),NULL,0,&dwByteRet,NULL,NULL);
	return sock;
end:
	WSACleanup();
	return rc;
}

int closeSocket(SOCKET sock)
{
	WSACleanup();
	closesocket(sock);
	return 0;
}

int recvBuffer(SOCKET fd,char *buf, int len) 
{
	return  recv(fd, buf, len, 0);
}

int sendBuffer(SOCKET fd, char *buf, int len)
{
	return send(fd, buf, len, 0);
}

int getData(char *buf, void *tcphdr, int len) 
{
	memcpy(tcphdr,buf, len);
	return 0;
}