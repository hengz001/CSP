
struct icCfg_str
{
	unsigned char SETAUX[60];
	unsigned char INITAUX[60];
	unsigned char CLOSEAUX[60];
	unsigned char AUXSTARTWRITE[60];
	unsigned char AUXENDWRITE[60];
	unsigned char DISABLEKEYBOARD[60];
	unsigned char ENABLEKEYBOARD[60];
	unsigned char DRVCOMM[60];
};

#define OP_OK      	    0
#define ERR_OPENCOMM		-0x10
#define ERR_READ         	 -0x80
#define ERR_WRITE         	-0x81
#define ERR_COMAND        	-0x82
#define ERR_PASS          	-0x83
#define ERR_TIMEOUT       	-0x84
#define ERR_CHECK         	-0x85
#define ERR_NOCARD        	-0x86
#define ERR_LESS          	-0x87
#define ERR_COMM          	-0x88
#define ERR_TYPE	      	-0X89
#define ERR_BCC           	-0X8A
#define ERR_CARDNO        	-0X8B
#define ERR_PULLCARD      	-0X8C
#define ERR_GENERAL       	-0X8D
#define ERR_HEAD          	-0X8E
#define ERR_LEN          	-0X8F
#define ERR_ADDRESS       	-0x90
#define ON		   			0x00
#define OFF		   			0x01

#define CMD_RST    		0x20
#define CMD_PTL	   		0x21
#define CMD_CNLREQ 		0x22
#define CMD_CARDBAUD	0x22
#define CMD_SLT_SAM		0x23

#define CMD_SWRITE	   	0x60
#define CMD_SREAD      	0x61
#define CMD_PWRITE	   	0x62
#define CMD_CHKCARD	   	0x63
#define CMD_CSC		   	0x64
#define CMD_RSC		   	0x65
#define CMD_WSC		   	0x66
#define CMD_REC 	   	0x67
#define CMD_CESC	   	0x68
#define CMD_RESC	   	0x69
#define CMD_WESC	   	0x6a
#define CMD_REEC	   	0x6b
#define CMD_RECC	   	0x6c
#define CMD_WPWR	   	0x6d
#define CMD_WPRD	   	0x6e
#define CMD_WRPB	   	0x6f
#define CMD_WWC		   	0x70
#define CMD_BLOW	   	0x71
#define CMD_FUSE1	   	0x72
#define CMD_FUSE2	   	0x73
#define CMD_PRD		   	0x74
#define CMD_PWR		   	0x75
#define CMD_SER		   	0x76
#define CMD_RDSTAU	   	0x77
#define CMD_ERAL	   	0x78
#define CMD_WRAL	   	0x79


#define CMD_RDVER	   	0xb0
#define CMD_BOUND	   	0xb1
#define CMD_PON		   	0xb2
#define CMD_POFF	   	0xb3
#define CMD_BEEP	   	0xb4
#define CMD_DVSC       	0xb5
#define CMD_WREEP	   	0xb6
#define CMD_RDEEP	   	0xb7
#define CMD_PULL	   	0xb8
#define CMD_STATUS	   	0xb9
#define CMD_FAKEFUS	   	0x80   //new   98.8.11


#define AT24C01		   	0x60
#define AT24C02 	   	0x61
#define AT24C04 	   	0x62
#define AT24C08 	   	0x63
#define AT24C16 	   	0x64
#define AT24C32 	   	0x65
#define AT24C64 	   	0x66

#define	CPU_CARD	   	0x20
#define	SAM_CARD		0x21

#define AT93C46A	   	0x68
#define AT93C46		   	0x69
#define AT93C57		   	0x6a
#define AT93C66		   	0x6b

#define AT45DB041 	   	0x6e

#define AT88SC101	   	0x71
#define AT88SC102	   	0x72
#define AT88SC1604	   	0x73

#define SLE4418		   	0x76
#define SLE4428		   	0x77
#define SLE4432		   	0x78
#define SLE4442		   	0x79
#define SLE4404		   	0x7a
#define SLE4406		   	0x7b

#define COMUNAL		   	0x80

#define PC_HEAD 	   	0xAA
#define DEV_HEAD	   	0x55
#define TIME_LIMITA	   	0.8
#define TIME_LIMITB	   	3
#define TIME_LIMITC     8

#define PARA_NO        	100
#define PARA_ICDEV0    	6666
#define PARA_ICDEV1    	8888
#define PARA_MD0        0
#define PARA_MD1        1

int gmn_ic_init( void );
int ic_exit(int fd) ;
unsigned char cr_bcc(int len, unsigned char *bcc_buffer);
int send_com(int icdev, int len, unsigned char *send_buffer);
int receive_com(int icdev, unsigned char *receive_buffer);
