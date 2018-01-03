#ifndef TCP_TOOLS_H
#define TCP_TOOLS_H

#define SEND_TIMEOUT		60	
#define RECV_TIMEOUT		90	
//#define MAX_MSGDATA			1024*8

#define	HSM_ERROR			(-1)
#define	HSM_OK				0
#define	HSM_ERR_SYSERR		(-999)
#define	HSM_ERR_OPEN		(-100)
#define	HSM_ERR_CLOSE		(-101)
#define	HSM_ERR_OPENED		(-102)
#define	HSM_ERR_CLOSED		(-103)
#define	HSM_ERR_INVALID		(-200)
#define	HSM_ERR_NOTEXIST	(-201)
#define	HSM_ERR_FILE		(-202)
#define HSM_ERR_MEMFULL		(-203)
#define	HSM_ERR_SOCK		(-204)
#define	HSM_ERR_WRITE		(-205)
#define	HSM_ERR_READ		(-206)
#define	HSM_ERR_LINE		(-207)
#define	HSM_ERR_TOOLONG		(-208)
#define	HSM_ERR_CHKSUM		(-209)
#define	HSM_ERR_IOCTL		(-210)
#define	HSM_ERR_SEND		(-211)
#define	HSM_ERR_RECV		(-212)
#define	HSM_ERR_UNKNOWN		(-213)
#define	HSM_ERR_TIMEOUT		(-300)
#define	HSM_ERR_BUSY		(-301)
#define	HSM_ERR_ZEROLEN		(-302)
#define	HSM_ERR_LENGTH		(-303)
#define	HSM_ERR_PUTMSGQ		(-400)
#define	HSM_ERR_GETMSGQ		(-401)
#define	HSM_ERR_INITMSGQ	(-402)
#define	HSM_ERR_GETQID		(-403)
#define	HSM_ERR_MSGHD		(-500)
#define	HSM_ERR_MSGTR		(-501)
#define	HSM_ERR_CMDRSP		(-502)
#define	HSM_ERR_RSPERR		(-503)

int comTcpSend(int sockfd, unsigned char *buffer, int *length, int timeout);

int comTcpReceive(int sockfd, unsigned char *buffer, int *length, int timeout);

int CloseHsmDevice(int comid);

int InitHsmDevice(char *tcpaddr, int port, int timeout);

int HsmCmdRun(int comid, int msghdlen, char * msghd, char *cmd, int cmdlen, char *rsp, int *rsplen);

void setIP(char *ip);

void setPORT(int port);

void getIP(char **ip);

int getPORT();

#endif