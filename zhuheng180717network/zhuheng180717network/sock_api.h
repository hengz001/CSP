
#ifndef __SOCK_API__
#define __SOCK_API__

#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <stdlib.h>
#include <string.h>

#pragma comment (lib,"ws2_32.lib")

typedef struct tcpheader
{
	unsigned short int sport;   //source address
	unsigned short int dport; //destination address
	unsigned int th_seq; //sequence number
	unsigned int th_ack; //acknowledge number
	unsigned char th_x2 : 4; //header length
	unsigned char th_off : 4; //reserved
	unsigned char  th_flag; //flags: URG ACK PSH RST SYN FIN 
	unsigned short int th_win; //window size
	unsigned short int th_sum; //check sum
	unsigned short int th_urp; //urgent pointer
}TCP_HDR;

typedef struct iphdr
{
	unsigned char h_lenver; //version & header length
	unsigned char ip_tos; //tos
	unsigned short int ip_len; //total length
	unsigned short int ip_id; //id
	unsigned short int ip_off; //offset
	unsigned char ip_ttl; //time to live
	unsigned char ip_p; //protocal
	unsigned short int ip_sum; //check sum
	struct in_addr ip_src; //source address
	struct in_addr ip_dst; //destination address
} IP_HDR; 

typedef struct udphdr
{
	unsigned short sport; //source port
	unsigned short dport; //destination port
	unsigned short len; //UDP length
	unsigned short cksum; //check sum(include data)
} UDP_HDR;


typedef struct icmphdr
{
	unsigned short sport;
	unsigned short dport;
	BYTE i_type;
	BYTE i_code;
	USHORT i_cksum;
	USHORT i_id;
	USHORT i_seq;
	ULONG timestamp;
}ICMP_HDR;

int getSocket();

int closeSocket(SOCKET sock);

int recvBuffer(SOCKET fd, char *buf, int len);

int sendBuffer(SOCKET fd, char *buf, int len);

int getData(char *buf, void *tcphdr, int len);

#endif