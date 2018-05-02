
int comTcpSvrSocketOpen(int port);

int comTcpAccept(int sockfd, ULONG *tcpaddr);

int comTcpSocketClose(int sockfd);

int comTcpReceive(int sockfd, UCHAR *buffer, int *length, int timeout);

int comTcpSend(int sockfd, UCHAR *buffer, int *length, int timeout);
