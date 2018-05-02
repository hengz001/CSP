#include "tcpSvr.h"

int comTcpSvrSocketOpen(int port){

	int oldsockfd;
	int value;
	struct sockaddr_in sin = {AF_INET};
	int namelen;

	//
	if((oldsockfd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		return (-1);
	}

	value = 1;
	if((setsockopt(oldsockfd,SOL_SOCKET,SO_REUSEADDR,&value,sizeof(value))) < 0){
		return (-1);
	}

	bzero(&sin,sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);

	if((bind(oldsockfd,(struct sockaddr*)&sin,sizeof(struct sockaddr_in))) < 0){
		return (-1);
	}
	namelen = sizeof(struct sockaddr_in);
	if(listen(oldsockfd,SOMAXCONN) < 0){
		return (-1);
	}

	return (oldsockfd);
}

int comTcpAccept(int sockfd, ULONG *tcpaddr)
{
	int namelen;
	int consockfd = -1;
	struct sockaddr_in cliaddr;
	struct linger tcp_linger;
	int bufSize;
	int value;
	int keepIdle = 5;
	int keepInterval = 5;
	int keepAlive = 1;	// KeepAlive
	int keepCount = phsmShm->hsmcfg.rCh.keepalive / keepInterval;
	int len;
	struct sockaddr tcp_peer;
	struct sockaddr_in *tcp_sin;

	namelen = sizeof(struct sockaddr_in);
	if((consockfd=accept(sockfd,(struct sockaddr*)&cliaddr,(socklen_t *)&namelen)) < 0){
		return (-1);
	}
	tcp_linger.l_onoff = 1;
	tcp_linger.l_linger = 0;
	setsockopt(consockfd, SOL_SOCKET, SO_LINGER, &tcp_linger, sizeof(struct linger));

	bufSize = HsmGetTcpBufSize();
	value = bufSize;
	setsockopt(consockfd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value));
	setsockopt(consockfd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));

	if((keepIdle=HsmTcpGetKeepaliveTimer()) > 0){
		keepInterval = keepIdle;
		setsockopt(consockfd, SOL_SOCKET, SO_KEEPALIVE, (void*)&keepAlive, sizeof(keepAlive));
		setsockopt(consockfd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
		setsockopt(consockfd, SOL_TCP, TCP_KEEPINTVL, (void*)&keepInterval, sizeof(keepInterval));
		setsockopt(consockfd, SOL_TCP, TCP_KEEPCNT, (void*)&keepCount, sizeof(keepCount));
	}

	len = sizeof(struct sockaddr);
	getpeername(consockfd,&tcp_peer,(socklen_t *)&len);
	tcp_sin = (struct sockaddr_in *)&tcp_peer;

	struct in_addr addrfd = tcp_sin->sin_addr;
	*tcpaddr = dot2local(inet_ntoa(addrfd));

	return (consockfd);
}

int comTcpSocketClose(int sockfd)
{
	if(sockfd > 0){
		shutdown(sockfd,2);
		return close(sockfd);
	}
	return 0;
}

int comTcpReceive(int sockfd, UCHAR *buffer, int *length, int timeout)
{
	int rc = 0;
	fd_set stSockReadReady;
	struct timeval stTimeOut;

	FD_ZERO(&stSockReadReady);
	FD_SET(sockfd,&stSockReadReady);
	if(timeout){
		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;

		select(sockfd+1,&stSockReadReady,NULL,NULL,&stTimeOut);
	}else{
		select(sockfd+1,&stSockReadReady,NULL,NULL,NULL);
	}

	if(!FD_ISSET(sockfd,&stSockReadReady)){
		*length = 0;
		rc = -1;
	}else{
		int rcvlen,ilen;
		UCHAR *p = buffer,*q;

		rcvlen = read(sockfd,p,*length);
		if(rcvlen > 0)
		{
			ilen = hex2short(p);
			if(ilen > *length){
				ilen = *length - 2;
			}

			p += rcvlen;

			q = (buffer + ilen + 2);

			while((q-p)>0){
				FD_ZERO(&stSockReadReady);
				FD_SET(sockfd,&stSockReadReady);
				// Set the timer
				stTimeOut.tv_sec = 1;
				stTimeOut.tv_usec = 0;

				select(sockfd + 1, &stSockReadReady, NULL, NULL, &stTimeOut);

				if (!FD_ISSET(sockfd, &stSockReadReady))
				{
					*length = 0;
					rc = -3;
					goto err;
				}else{
					rcvlen = read(sockfd, p, ilen);
					if (rcvlen <= 0) {
						*length = 0;
						rc = -4;
						goto err;
					}
					p += rcvlen;
				}
			}
			*length = p-buffer;
		}else{
			*length = 0;
			rc = -2;
		}
	}
	err:
		return (rc);
}

int comTcpSend(int sockfd, UCHAR *buffer, int *length, int timeout)
{
	int rc = 0;
	UCHAR *p = buffer, *q = buffer+*length;
	fd_set stSockWriteReady;
	struct timeval stTimeOut;

	FD_ZERO(&stSockWriteReady);
	FD_SET(sockfd, &stSockWriteReady);

	if(timeout > 0){
		stTimeOut.tv_sec = timeout;
		stTimeOut.tv_usec = 0;
		select(sockfd+1,NULL,&stSockWriteReady,NULL,&stTimeOut);
	}else{
		select(sockfd+1,NULL,&stSockWriteReady,NULL,NULL);
	}

	if(!FD_ISSET(sockfd, &stSockWriteReady))
	{
		return -1;
	}else{
		int len;

		do{
			FD_ZERO(&stSockWriteReady);
			FD_SET(sockfd, &stSockWriteReady);

			stTimeOut.tv_sec = 1;
			stTimeOut.tv_usec = 0;
			if(!FD_ISSET(sockfd,&stSockWriteReady)){
				rc = -2;
				break;
			}else{
				len = write(sockfd,p,(q-p));
				if(len<0){
					rc = -3;
					break;
				}
				p += len;
			}
		}while((q-p)>0);
	}
	*length = p -buffer;
	return (rc);
}



