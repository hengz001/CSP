#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

int HsmSendToSocket(int sockfd, unsigned char *buffer, int *length, int timeout);

int HsmReceiveFromSocket(int sockfd, unsigned char *buffer, int *length, int timeout);

/*** Tcp/IP Server Socket Open Function ***/
int comTcpSvrSocketOpen(char *tcpaddr, int port);

/*** Tcp/IP Client Socket Open Function ***/
int comTcpCliSocketOpen(char *tcpaddr, int port, int timeout);

int comTcpAccept(int sockfd, char *alCliaddr);

/*** Tcp/IP Common Send Fnction ***/
int comTcpSend(int sockfd, unsigned char *buffer, int *length, int timeout);


/*** Tcp/IP Common Receive Fnction ***/
int comTcpReceive(int sockfd, unsigned char *buffer, int *length, int timeout);

/*** Tcp/IP Common Socket Close Fnction ***/
int comTcpSocketClose(int sockfd);




