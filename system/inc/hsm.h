#ifndef	__RACAL_HSM_H__
#define	__RACAL_HSM_H__

#include <openssl/md5.h>
#include "ssm.h"

#define __RSA_MODULUS_LEN4096__

//#define __DEBUG__
#define __MAKE_PRODUCT__
#define _MAKE_BUSYBOX_

#define __USE_SM4__

//#define _USE_NET_PRINTER_

//#define	__TSM__
//#define __EMBEDED__
//#define __TWO_PORTS__
//#define	__TRACE__

#define 	__HSM_GANDD__	//捷德

//#define	__HSM_NBS__
//#define __NO_JKIC__
//#define __NO_IC__

//#define __HSM_SHEBAOBU__	//社保部
//#define __HSM_SHEBAO__	//社保? 编译不正确

//#define __ZIHEXIN__
//#define __WAIJIAOBU__   //for waijiaobu ECC added 20131101
//#define __CFCA__   //for CFCA added 20130813
//#define __HSM_ZT__

//#define __BJ_YIKATONG__	//一卡通

//#define __GA3SUO__ //for gong an 3 suo
//#define	__ICBC_APP__
//#define	__HSM_TEST__
//#define	__IC_DATA_DEF__

// If not use DOC, undefine this
//#define	__DOC__
// If not use Compact-Flash, undefine this
#define	 __CFCARD__
// If not use DISK ON MODULE, undefine this
//#define	__DOM__
// If use hardware RSA, undefine this
//#define	__RSA_SOFTWARE__

#define	__ALGO_SCB2__
#define	__HSM_HASH__

#define __NEW_KSTORE__

//#define	__HSM_NEW_CONFIG__
//#define	__HSM_NEW_CONFIG__


//heng.z modification 17-5-2 14:32
#define __NEW_SM2__
//17-10-19
#define __GMB_ALGORITHM__

#if defined (__DOC__)
#define	__HSM_DEVFS__
#endif

#if defined (__CFCARD__) || defined(__DOM__)
#undef	__HSM_DEVFS__
#endif

#if defined (__CFCARD__)
#undef	__DOM__
#endif

#if defined (__DOM__)
#undef	__CFCARD__
#endif

#if defined (__HSM_DEVFS__)
#undef	__CFCARD__
#undef	__DOM__
#endif

/* End of message */
//#define EM      (0x19)
/* HSM buffer length */
#define LEN_MAX_BUF     		(32*1024)		/* Max. send & receive buffer length */
#define	 LEN_MAX_RSADATA		(32*1024)		/* Max. RSA data length */
#define HSM_TCP_SENDTIMER       2		/* Send timer 2 seconds */

#ifdef	__RSA_MODULUS_LEN4096__
//#define MAX_DER_BUF     	(1024*5)
#define MAX_DER_BUF     	(1024*3)
#else	/* __RSA_MODULUS_LEN4096__ */
#define MAX_DER_BUF     	3072
#endif	/* __RSA_MODULUS_LEN4096__ */

#if defined(__NO_JKIC__) || defined(__CFCA__)

//#define MAX_RSAKEY		41

#elif defined  (__HSM_SHEBAO__) && !defined   (__HSM_ZT__)

//#define MAX_RSAKEY		10
#define	MAX_TK_INDEX		10
#define	LEN_KS			((1+MAX_TK_INDEX*2)*32)

#elif defined  (__HSM_SHEBAO__) && defined   (__HSM_ZT__)

//#define MAX_RSAKEY		2
#define	MAX_TK_INDEX		10
#define	LEN_KS			((1+MAX_TK_INDEX*2)*32)

#elif defined	(__HSM_ZT__)

//#define MAX_RSAKEY		2
#define	MAX_TK_INDEX		10
#define	LEN_KS			((1+MAX_TK_INDEX*2)*32)

#elif !defined  (__HSM_SHEBAO__) && !defined   (__HSM_ZT__)

//#ifdef	__RSA_MODULUS_LEN4096__
////#define MAX_RSAKEY		24			//新密钥卡最大24个
////#define MAX_RSAKEY		(11+8)			// GMN06262009Ro
//#else	/* __RSA_MODULUS_LEN4096__ */
//#define MAX_RSAKEY		(11+8)			// GMN06262009Ro
//#endif	/* __RSA_MODULUS_LEN4096__ */

#endif	/* __NO_JKIC__ */

#define MAX_RSAKEY			(65536/sizeof(RSAKey))		//RSA密钥存储数，64kb
#define MAX_RSAKEY_INDEX	(MAX_RSAKEY-1)

#define MAX_SM2KEY			(65536/sizeof(SM2Key))		//存储区64k，SM2私钥个数
#define MAX_SM2_INDEX     	(MAX_SM2KEY-1)
#define NO_INDEX			999		//非索引存储
#define NO_INDEX_RSA		99		//非索引存储

/* Commonly used option */

#ifdef	__EMBEDED__
#define	 LEN_USERSTORE	(8192)
#else
#define	 LEN_USERSTORE	(98304)		//96kb
#endif

#define LEN_CARDMEM		(256*1024)		/* Total card memory */
#define	 LEN_KEYSTORE	(64*1024)

//新加密卡缓存大小
#define NVRAM_SIZE	(1024*32)
#define LPSRAM_SIZE	(1024*256)

//JK密钥长度(算法1字节+密钥24字节+校验2字节）密钥不足24字节的补FF
#define LEN_JK_KEY	(LEN_DES_TRIPLE+1+2)

//JK密钥和SM4密钥使用相同存储区,第一个64kb区间2448b开始的区域
//#ifdef __NO_JKIC__
#define  HSM_KSTORE_SM4_OFFSET  (2448)	/* 2448bstart */
//#else
#define  HSM_KSTORE_JK_OFFSET  (2448)	/* 2448bstart */
//#endif

//#define  HSM_KSTORE_RSA_OFFSET  (3*1024)
//#define  HSM_KSTORE_RSA_OFFSET  (2448)	/* 0x990 (2448=51*2*24) */
#define  HSM_KSTORE_RSA_OFFSET  (64*1024)	/* 64KB开始64kb */
#define  HSM_KSTORE_SM2_OFFSET  (128*1024)	/* 128KB开始64kb */
#define  HSM_KSTORE_IC_OFFSET  (192*1024)	/* 194KB开始64kb */

//SM4密钥长度(128bit=16byte)，因同时要存储协商密钥，最大定为32b，密钥长256位
//兼容DES密钥的存储，第一字节为算法类型
#define LEN_SHARE_STORE_KEY   (sizeof(SM2XSKey) + 1)	//共享存储区密钥块长度
#define LEN_SM4_KEY 16

//SM4密钥个数--共享存储区密钥个数
#define MAX_SM4KEY			((65536-2448)/LEN_SHARE_STORE_KEY)
#define MAX_SM4KEY_INDEX	MAX_SM4KEY - 1
//SM4 not save
#define NOT_SAVE_SM4 		0x999

#ifndef __NO_IC__
//#define	MAX_JK_INDEX	(1000)
//#define	MAX_JK_INDEX	((65536-2448-MD5_DIGEST_LENGTH)/LEN_JK_KEY)
#define	 MAX_JK_INDEX	MAX_SM4KEY_INDEX	//与SM4同一缓存，按SM4计算
#else	/* __NO_IC__ */
//#define	MAX_JK_INDEX	(1000+2427)
#define	MAX_JK_INDEX	((65536-2448)/LEN_JK_KEY)
#endif	/* __NO_IC__ */

/* 100 indices for JK key - GMN07252004Ro */
//#define	LEN_JKSTORE	(LEN_JK_KEY*MAX_JK_INDEX)		//JK缓存size
#define	 LEN_JKSTORE	(LEN_SHARE_STORE_KEY*MAX_SM4KEY)		//JK缓存size 2017-10-19modify

//#define	LEN_PRTFORM	(299)
#define	LEN_PRTFORM	(1024)
// GMN12012006Ro
#define	 LEN_MAX_LINE	255
#define MAX_LMKS		(50)
#define MAX_LMKVARIANTS	10
#define MAX_LMKSINDEX	(MAX_LMKS-1)
//#define MAX_KEYTYPE_MKIDX	(0x22)
#define MAX_KEYTYPE_MKIDX	(0x2C)	/* Refer to rclKeyType.c */

/* GMN - 20050120 SL */
#define RACAL_RSA_KEYTYPE_MAX	0x2C
#define RACAL_RSA_KEYVAR_MAX	0x09

#define DATACARD_LMK_OFFSET     0x1C

// Max. IC transport key index - GMN11172006Ro
#define	MAX_TRANSPORT_KIDX	5

#define	FAULT_INDICATOR_ON	1
#define	FAULT_INDICATOR_OFF	0

#ifndef	__NO_IC__
#ifdef	__IC_DATA_DEF__

#define	__IC_DATA_LENGTH__	264

typedef struct
{
	unsigned short len;
	UCHAR data[__IC_DATA_LENGTH__];
	UCHAR crc[2];
} icDataStr;

#define	__MAX_IC_DATA_IDX__	512
#define	__IC_DATA_RECORD_LEN__	(sizeof(icDataStr))

#define	__IC_DATA_LMK_OFFSET__	(__MAX_IC_DATA_IDX*__IC_DATA_RECORD_LEN__)

#endif	/* __IC_DATA_DEF__ */
#endif	/* __NO_IC__ */

/* Supported HSM communication server */
#define PROG_MAIN_TCP			1
#define	 PROG_MAIN_V24			2
#define	 PROG_MAIN_SNA			3
#define	 PROG_MAIN_X25			4
#define	 PROG_MAIN_MON			5
#define	 PROG_MAIN_TCP_NH		6
#define	 PROG_MAIN_TCP_WL		7
#define	 PROG_MAIN_POS			8
#define	 PROG_START_TOMCAT		9
#define	 PROG_STOP_TOMCAT		10

#define HOSTCMD_IC_BCD			0
#define HOSTCMD_IC_HEX			1
#define MAX_SOL_BATCH			2048

/* Application functionality description */
/* Protocol definitions */
#define	 PROTOCOL_TCP 			0x80000000L
#define	 PROTOCOL_V24 			0x40000000L
#define	 PROTOCOL_SNA 			0x20000000L
#define	 PROTOCOL_X25 			0x10000000L

#define	 PRINTER_USB     		0x08000000L
#define	 PRINTER_NET     		0x04000000L
#define SUPPORT_ABC      		0x02000000L
#define RACAL_USE_JK_INDEX  	0x01000000L


#define	 KEY_MEM_256 			0x00800000L
#define	 KEY_MEM_128 			0x00400000L
#define	 PRINTER_SERIAL 		0x00200000L
#define	 PRINTER_PARALLEL 		0x00100000L

/* Max. TCP connection number */
#define	 MAX_CON_4096 			0x00080000L
#define	 MAX_CON_2048 			0x00040000L
#define	 MAX_CON_1024 			0x00020000L
#define	 MAX_CON_512 			0x00010000L

#define SUPPORT_IC_EXPORT		0x00008000L	/* Support IC clear key export - GMN11252008Ro */
#define	 SUPPORT_ICBCASIA 		0x00004000L	/* ICBC Asia */
#define	 SUPPORT_INTERBANK 		0x00002000L	/* Internet Banking */
#define	 SUPPORT_POSKMGR		0x00001000L	/* POS Key Management */

/* Command supported */
#define	 SUPPORT_GANDD			0x00000800L
#define	 SUPPORT_EMV2KDEMO		0x00000400L
#define	 SUPPORT_DATACARD		0x00000200L
#define	 SUPPORT_RSA			0x00000100L

#define	 SUPPORT_RACAL 			0x00000080L
#define	 PROTOCOL_TCP_WL 		0x00000040L		//IC/JK兼容命令集带命令长度
#define	 PROTOCOL_TCP_NH 		0x00000020L		//允许使用IC/JK兼容命令集
#define	 GMN_CRYPTO				0x00000010L	/* Hardware crypto card existed - GMN08122004Ro */

//删除金卡功能，增加B/S管理端
//#define	SUPPORT_JK 			0x00000008L
#define	 SUPPORT_BSM			0x00000008L
#define	 SUPPORT_PBOC 			0x00000004L
#define	 SUPPORT_IC_ISSUE_CARD	0x00000002L
#define	 SUPPORT_STK 			0x00000001L

/* Atalla Variant */
#define	 ATALLA_1BYTE_VARIANT	0
#define	 ATALLA_2BYTE_VARIANT	1

/* Async protocol mode of operation */
#define V24_MODE_NORMAL			1		/* Host async normal mode */
#define V24_MODE_TRANSPARENT	2		/* Host async transparent mode */
#define TCP_MODE_TRANSPARENT	3		/* Host async transparent mode */

/* Sense bytes -  for gmnMon GMN05082004 */
#define	HSM_STATE_NORMAL		0		/* Hsm is in normal state */
#define	HSM_STATE_ARMED			1		/* HSM is in armed state - GMN04222004 */
#define	HSM_STATE_OFFLINE		2		/* HSM is in Offline - GMN05082004 */

#define SIG_HZ_SEND         (56)
#define SIG_HZ_RECV         (57)
#define SIG_THREADKILL  	(60)
#define SIG_HSM_INTERRUPT	(61)		/* HSM state changed - GMN05082004 */
#define SIG_HST_BAKRESTR  	(62)		//密钥备份、恢复(Host端)
#define SIG_MGR_BAKRESTR  	(63)		//密钥备份、恢复（管理端）
//#define SIG_MGR_TEST        (64)

/* kstore card I/O control */
/* 定义幻数 */
#define CARD_IOC_MAGIC  'g'

/* 定义命令 */
#define CARD_ALERT          	    _IOR(CARD_IOC_MAGIC, 1, int)	//警戒状态
#define CARD_OFFLINE            	_IOR(CARD_IOC_MAGIC, 2, int)	//脱机状态
#define CARD_BLOCKALERT         	_IOR(CARD_IOC_MAGIC, 3, int)	//同CARD_ALERT
#define CARD_BLOCKOFFLINE       	_IOR(CARD_IOC_MAGIC, 4, int)	//同CARD_OFFLINE
#define CARD_FAULTINDICATOR			_IOWR(CARD_IOC_MAGIC, 5, int)	//故障指示
#define CARD_BLOCKDANGER			_IOWR(CARD_IOC_MAGIC, 6, int) 	//
#define CARD_ROOM					_IOWR(CARD_IOC_MAGIC, 7, int) 	//
#define CARD_DANGER					_IOWR(CARD_IOC_MAGIC, 8, int) 	//
#define CARD_RANDOM             	_IOWR(CARD_IOC_MAGIC, 9, int)	//取得随机数32位（随机数1+随机数2）
#define CARD_VOLTAGE            	_IOWR(CARD_IOC_MAGIC, 10, int)	//取得电池电压
#define CARD_STATUS_INDICATOR   	_IOWR(CARD_IOC_MAGIC, 11, int)	//状态灯
#define _SM3_HASH_MESSAGE_			_IOWR(CARD_IOC_MAGIC, 12, int)	//SM3运算
#define _SM2_GENKEY_				_IOWR(CARD_IOC_MAGIC, 13, int)	//SM2生成密钥对
#define _SM2_SING_					_IOWR(CARD_IOC_MAGIC, 14, int)	//SM2生成签名
#define _SM2_VERIFY_				_IOWR(CARD_IOC_MAGIC, 15, int)	//SM2验证签名
#define _SM2_ENCRYPT_				_IOWR(CARD_IOC_MAGIC, 16, int)	//SM2公钥加密
#define _SM2_DECRYPT_				_IOWR(CARD_IOC_MAGIC, 17, int)	//SM2私钥解密
#define _SM2_EXCHANGE_				_IOWR(CARD_IOC_MAGIC, 18, int)	//SM2密钥协商
#define CARD_SM2INIT				_IOWR(CARD_IOC_MAGIC, 97, int) 	//SM2初期化
#define CARD_SM3INIT				_IOWR(CARD_IOC_MAGIC, 98, int) 	//SM3初期化
#define CARD_TEST					_IOWR(CARD_IOC_MAGIC, 99, int) 	//SM2、SM3缓存读写测试


/* Multi-algorithm definitions */
#define ALGO_DESTDES    	(0x00)
#define ALGO_SSF33      	(0x01)
#define ALGO_SSF10      	(0x02)
#define ALGO_SM1      		(0x03)
#define ALGO_AES      		(0x04)
#define ALGO_SM4      		(0x05)
#define ALGO_SM9      		(0x06)
#define ALGO_SM2XS     		(0x09)	//SM2协商密钥

/* Supported hardware crypto chips */
#define CHIP_SSP04B			0x00000008L
#define CHIP_SSP05C			0x00000004L
#define CHIP_HIFN7902		0x00000002L
#define CHIP_HIFN6500		0x00000001L
#define CHIP_SSX30B			0x00000010L
#define CHIP_SM2			0x00000020L


/* length of LMKs for each triplet */
#define LEN_LMK		LEN_DES_TRIPLE
/* HSM serial number */
#define	LEN_HSM_SERNO	18

#ifdef	__EMBEDED__
#define	MAX_TCP_CONNECT_NO	1024	/* Max. TCP connections */
#else
#define	MAX_TCP_CONNECT_NO	4096	/* Max. TCP connections */
#endif

/* IC card related definitions */
#define	IDENT_STRING	"3F0401D9D07DA466"
#define	LEN_ICIO	(16*4)
#define	LONG_BEEP	50
#define	SHORT_BEEP	10
#define	LEN_CMDCODE	2	/* Length of command code filed */
#define	LEN_CMDLEN	2	/* Length of command length field */

/* defined in GetDefaultKeySchem() GMN12112003Ro */
#define	KEYSCHEM_COMPATAB	1
#define	KEYSCHEM_ENHANCED	2

/* Clear PIN definitions */
#define	CLEAR_PIN_ALLOW	1	/* NG allowed - GMN12162003Ro */
#define	CLEAR_PIN_NOTAL	2	/* NG not allowed  - GMN12162003Ro */

/* PIN algorithm */
#define PIN_ALGO_A	1
#define PIN_ALGO_B	2


/* Shared memory parameters */
#define	HSM_SHMKEY	((key_t)0x4a11)
#define	HSM_SHMPER	0666

/* Character code option */
#define	CHARSET_ASCII	1
#define	CHARSET_EBCDIC	2
#define	CHARSET_IBM1388	3

/* ZMK & LMK encryption option */
#define	ENCRYPTED_UNDER_LMK	1
#define	ENCRYPTED_UNDER_KEK	2
#define	HOSTCMD_SYNTAX_SCAN	3

/* Key scheme length option */
#define	KSCHEM_SINGLE	8
#define	KSCHEM_DOUBLE	16
#define	KSCHEM_TRIPLE	24

/* Authorization option */
#define	NOT_AUTHORIZED	0
#define	AUTHORIZED	1

/* Get the current authorization mode: AUTH_PASS, AUTH_CARD */
#define	AUTH_CARD	0
#define	AUTH_PASS	1

/* Clear PIN option */
#define	ECHO_NOECHO	2
#define	ECHO_ON		1
#define	ECHO_OFF	0	//change by shw 0312

/* PIN mailer printer definitions */
#define	PRINT_SERIAL	0
#define PRINT_PARALLEL	1
#define PRINT_USB	2
#define PRINT_NET	3

/* Key odd parity processing option */
#define	NOTE_PAR_ERROR	1
#define	NOTE_PAR_WARN	2


/* Definitions for hsm state */
#define HSM_ONLINE	1
#define HSM_OFFLINE	2

/* definitions for trailer - GMN01202005Ro */
#define	NOT_ALLOWED	0
#define	HSM_ALLOWED	1

/* Define the maximium field for PIN mailer */
#define	MAX_PM_FIELD	32

/* PIN mailer option */
#define RESPONSE_BEFORE_PRINT	1
#define RESPONSE_AFTER_PRINT	2


#define	PM_SCAN		1
#define	PM_PRINT	2

/* Definitions for version of DUKPT */
#define	DUKPT_V1	1
#define	DUKPT_V2	2

#define	MAX_CLIENTS	50	/* Max. no of TCP clients 09242003Ro */

#define	V24_POS_SERVER	1	/* POS key management server mode */
#define	V24_POS_CLIENT	0	/* POS key management client mode */

#define	V24_TIMEOUT	5	/* Time Gap between send and receive while using v.24 */

/* ANSI X9.17 Psedo-Random Number Generation */
//#define	SECRET_SEED "19621224"

/* Port definition */
#ifdef	__MAKE_PRODUCT__

#ifdef	__TWO_PORTS__
#define	CONSOLE_PORT	"/dev/tts/0"
#define	ICCARD_PORT		"/dev/tts/1"
#define	AUXILIARY_PORT	"/dev/tts/2"
#define	HOSTV24_PORT	"/dev/tts/3"
#define	PRINTER_PORT	"/dev/printers/0"

#else	/* __TWO_PORTS__ */

#ifdef	__HSM_DEVFS__

#define	CONSOLE_PORT	"/dev/tts/0"
#define	AUXILIARY_PORT	"/dev/tts/2"
#define	ICCARD_PORT		"/dev/tts/3"
#define	HOSTV24_PORT	"/dev/tts/1"
#define	PRINTER_PORT	"/dev/printers/0"

#else	/* __HSM_DEVFS__ */

#ifdef	__TSM__

#define	CONSOLE_PORT	"/dev/ttyS0"
#define	AUXILIARY_PORT	"/dev/ttyS2"
#define	ICCARD_PORT		"/dev/ttyS1"
#define	HOSTV24_PORT	"/dev/ttyS3"
#define	PRINTER_PORT	"/dev/lp0"

#else	/* __TSM__ */

#define	CONSOLE_PORT	"/dev/ttyS2"	//管理端口Com3
#define	AUXILIARY_PORT	"/dev/ttyS0"	//串口打印Com0
#define	ICCARD_PORT		"/dev/ttyS3"	//IC读取端口Com4
#define	HOSTV24_PORT	"/dev/ttyS1"	//V24端口Com2
#define	PRINTER_PORT	"/dev/lp0"		//并行打印口

#endif	/* __TSM__ */

#endif	/* __HSM_DEVFS__ */

#endif	/* __TWO_PORTS__ */

#else	/* __MAKE_PRODUCT__ */

#ifdef	__TSM__

#define	CONSOLE_PORT	"/dev/ttyS0"
#define	AUXILIARY_PORT	"/dev/ttyS2"
#define	ICCARD_PORT		"/dev/ttyS1"
#define	HOSTV24_PORT	"/dev/ttyS3"
#define	PRINTER_PORT	"/dev/lp0"

#else	/* __TSM__ */

#define	CONSOLE_PORT	"/dev/ttyS0"
#define	AUXILIARY_PORT	"/dev/ttyS2"
#define	ICCARD_PORT		"/dev/ttyS3"
#define	HOSTV24_PORT	"/dev/ttyS1"
#define	PRINTER_PORT	"/dev/lp0"

#endif	/* __TSM__ */

#endif	/* __MAKE_PRODUCT__ */

//heng.z 17-5-10 10:13
#define	AUXUSB0_PORT	"/dev/usblp0"
#define	AUXUSB1_PORT	"/dev/usb/lp0"

#define	PORT_CONSOLE	1
#define	PORT_AUXILIARY	2
#define	PORT_HOSTV24	3

/* Used in secFileIO.c & mgrConfig.c */
#define FILE_MASTERKEY  "ksCard.cfg"
#define FILE_HSMCONFIG  "ksParm.cfg"
#define FILE_HSMKSTORE  "ksStor.cfg"
#define LEN_BLOCKSIZE   512

/* RSA option - BEGIN */

#ifndef	MDC2_DIGEST_LENGTH
#define	MDC2_DIGEST_LENGTH 16
#endif

#ifndef	MD5_DIGEST_LENGTH
#define	MD5_DIGEST_LENGTH 16
#endif

#ifndef	MD2_DIGEST_LENGTH
#define	MD2_DIGEST_LENGTH 16
#endif

#ifndef	SHA1_DIGEST_LENGTH
#define	SHA1_DIGEST_LENGTH 20
#endif

#ifndef	RMD128_DIGEST_LENGTH
#define	RMD128_DIGEST_LENGTH 16
#endif

#ifndef	RMD160_DIGEST_LENGTH
#define	RMD160_DIGEST_LENGTH 20
#endif

#ifndef	SM3_DIGEST_LENGTH
#define	SM3_DIGEST_LENGTH 32
#endif

//密钥模式
#define SIG_ALGO_RSA    1
#define SIG_ALGO_ECC    2
#define SIG_ALGO_SM2    3

//哈希算法标识符
#define HASH_MD2		0
#define HASH_SHA1       1
#define HASH_MD5        2
#define HASH_ISO10118_2 3
#define HASH_NOHASH     4
#define HASH_SHA224		5
#define HASH_SHA256		6
#define HASH_SHA384		7
#define HASH_SHA512		8
#define HASH_MD4        9
#define HASH_RIPEMD128	10
#define HASH_RIPEMD160	11
#define HASH_RIPEMD256	12
#define HASH_RIPEMD320	13
#define HASH_SM3		14

//填充模式标识符
#define PAD_NOPAD       	0
#define PAD_PKCS1       	1
#define	PAD_OAEP			2
#define	PAD_PSS				3
#define PAD_CKM_RSA_PKCS1	4
#define	PAD_ANSI_X931		5
#define PAD_EMV2000     	6


#define  RSA_KEY_SIGNATURE		'0'
#define  RSA_KEY_MANAGEMENT		'1'
#define  RSA_KEY_BOTH			'2'
#define  RSA_KEY_BOTH_OUT		'3'
#define  ECC_KEY_BOTH			'3'
#define  SM2_KEY_BOTH       	'4'

#define	 HSM_KSTORE_MAX_RSAKEY	MAX_RSAKEY

#ifdef  __RSA_MODULUS_LEN4096__
#define  HSM_MAX_N_LEN	4096
#else   /* __RSA_MODULUS_LEN4096__ */
#define  HSM_MAX_N_LEN	2048
#endif  /* __RSA_MODULUS_LEN4096__ */

#define  HSM_MIN_N_LEN	192

#define  HSM_MAX_E_LEN	HSM_MAX_N_LEN
#define  HSM_MIN_E_LEN	2

//#define	 HSM_MAX_RSA_KEY (HSM_MAX_N_LEN/8+1)
#define	 HSM_MAX_RSA_KEY 	(HSM_MAX_N_LEN+7)/8
#define	 HSM_HALF_RSA_KEY	((HSM_MAX_RSA_KEY+1)/2)

#define	MODE_IDX_3BYTES	0
#define	MODE_IDX_4BYTES	1

#define	MODE_USTORE	0
#define	MODE_KSTORE	1

#define	LEN_IDX_3BYTES	3
#define	LEN_IDX_4BYTES	4

#define	 LMK_TYPE_OLD	0
#define	 LMK_TYPE_NOW	1

#define	 RSA_PUBLIC_KEY		0
#define	 RSA_PRIVATE_KEY	1

#define	 RSA_ENCRYPT		1
#define	 RSA_DECRYPT		0

typedef struct
{
	byte	rsa_key_type;	/* '0' - Signature only,
				   	   	   	   '1' - Key management only,
				   	   	   	   '2' - Both signature and key management */
	byte    n[HSM_MAX_RSA_KEY];
	byte    d[HSM_MAX_RSA_KEY];
	byte    e[HSM_MAX_RSA_KEY/2];
	byte    p[HSM_MAX_RSA_KEY/2];
	byte    q[HSM_MAX_RSA_KEY/2];
	byte    d1[HSM_MAX_RSA_KEY/2];
	byte    d2[HSM_MAX_RSA_KEY/2];
	byte    inverse[HSM_MAX_RSA_KEY/2];

	int   	nlen; /* 0 means invalid */
	int   	dlen;
	int   	elen;
	int   	plen;
	int   	qlen;
	int   	d1len;
	int   	d2len;
	int   	inverselen;
} RSAKey;

typedef struct
{
	byte key_type;		/* 0：签名; 1：密钥管理；2：签名、密钥管理和协商；3：协商 */
	int  privlen;		//private key length
	byte privkey[32+1];	//private key
	int  publen;		//public key length
	byte pubkey[64+1];	//public key
} SM2Key;

typedef struct
{	//SM4按固定长16字节保存，不需长度。本结构实际为存储SM2协商密钥
	int  klen;		//key length
	byte key[32];	//key
} SM2XSKey;

typedef struct
{
	byte	format;
	byte	key_usage;	/* '1' - Signature only,
				   	   	   '2' - Key management only,
				   	   	   '3' - Both signature and key management */
	byte	hash_id[2];	/* Hash Identifier */
	UINT	key_len;
	byte    key[MAX_DER_BUF];
} HMACKey;

/* RSA option - END */
typedef struct{
    ULONG stateIV[8];           /*state (ABCDEFGH)*/
    ULONG count[2];             /*number of bits, modulo 2^64 (lsb first) */
    ULONG T[64];                /* the initial const list T.*/
    unsigned char buffer[64];   /* input buffer */
}SM3_CONTEXT;

typedef struct{
    int datalen;           		/* input data length */
    unsigned int buffer[MAX_DER_BUF/4];   	/* input buffer */
}SM3_MESSAGE_INFO;

struct cfgMasterKeyFile_t
{
	unsigned char LMKs[51][LEN_LMK];
	unsigned char oldLMKs[51][LEN_LMK];
};


struct cfgHsmKeyStore_t
{
	uchar kstore[LEN_KEYSTORE];     /* Key storage : 10312003Ro */
	uchar cv[MD5_DIGEST_LENGTH];
};

struct cfgHsmJKeyStore_t
{
	uchar kstore[LEN_JKSTORE];     /* JK Key storage : GMN07252004Ro */
	uchar cv[MD5_DIGEST_LENGTH];	//校验值
};

/* IC card data structure */
struct mgrIcCard_t
{
	uchar len[2];
	uchar passwd[16];
	uchar cv[8];
};

enum {
	K_ZMK	=	1,
	K_ZMK_C,
	K_KML,
	K_ZPK,
	K_PVK,
	K_TPK,
	K_TMK,
	K_CVK,
	K_CSCK,
	K_TAK,
	K_WWK,
	K_ZAK,
	K_BDK,
	K_MK_AC,
	K_MK_SMI,
	K_MK_SMC,
	K_MK_DAK,
	K_MK_DN,
	K_ZEK,
	K_ZE_IV,
	K_ZEK_C,
	K_ATM_BK,
	K_TEK,
	K_TE_IV,
	K_TEK_C,
	K_RSA_SK,
	K_AN_PIN,
	K_DSK,
	K_DS_IV,
	K_DSK_C,
	K_DEK,
	K_DEK_IV,
	K_LPK,
	K_MAX_KEY
};

#define	MAX_IC_STORAGE		(1024*7)
#define	MAX_IC_STORAGE64	(1024*32)

/* Definitions for smart card type identity */
enum
{
	IC_CARD_BLANK = 0,	/* Blank card */
	IC_CARD_LMK,		/* LMK component card */
	IC_CARD_AUTH,		/* Authorization card */
	IC_CARD_ZMK,		/* ZMK component card */
	IC_CARD_TEST,		/* Test card */
	IC_CARD_MGR,		/* Management card */
	IC_CARD_DATA,		/* Key storage card */
	IC_CARD_DATA_USR,	/* User storage card */
	IC_CARD_DATA_JK,	/* JK keys backup card */
	IC_CARD_DATA_IC,	/* IC keys backup card */
	IC_CARD_DATA_STK,	/* STK keys backup card */
	IC_CARD_UPDATE,		/* PROGRAM UPDATE CARD */
	IC_CARD_RSA,		/* RSA key pair backup card - GMN03022005Ro */
	IC_CONF_PARM		/* CONFIGURATION PARM CARD */
};

/* HSM shared memory handler */
int	hsmShmID;

/* Term ID to JK key index relationship - GMN10202006Ro */
typedef struct
{
	char termid[8];
	USHORT index;
} termIndex_t;

/* TMK and EDK index for CMB CHINA - GMN10202006Ro */
typedef struct
{
	UCHAR  tmk_idx;		/* TMK index for CMB CHINA - GMN1020200Ro */
	UCHAR  edk_idx;		/* EDK index for CMB CHINA - GMN1020200Ro */
} cfgCMB_t;

/* LMKs smart card identity structure */
typedef	struct
{
	char vendor_id[16];
	char version[4];
	char issue_time[6];
	char issue_date[6];
	char user_id[35];
	char issuer_id[35];
	char udata_len[4];
	char udata_used[4];
	char usage_id;	/* 0 - Blank Card, 1 - LMK, 2 - Auth, 3 - ZMK */
} icInfo_t;

/* Old RACAL Key Type Codes and new Key Type */
typedef struct
{
	int  kTypeIdx;
	char kTypeCode[2+1];
	char keyType[3+1];
} keyTypeCodes_t;

/* RACAL key type code definition */
typedef struct
{
	int keyname;
	char keytype[4];
} racal_keytype_t;

typedef	struct
{
	int csize;
	int parity;
	int stopbit;
	int flow;	/* Flow control - GMN01042003Ro */
} word_format_t;

typedef	struct
{
	int baudrate;
	word_format_t parm;
} port_parm_t;

typedef struct
{
	port_parm_t port_parm;	/* Port parameters */
	char printer_ip [256];  // net printer IP, by 20170511
	int  printer_port;		// net printer PORT, by 20170511
	int fd;			/* File handler for async port */
} async_port_t;

typedef struct
{
	unsigned long ip;
	unsigned char hw[6];
} client_t;			/* GMN01042003Ro */

/* RACAL host configuration */
typedef	struct
{
	int  msghd_len;			/* Message Header Length 1-255 */
	UCHAR trailer;			/* Message trailer - GMN01202005Ro */
	UCHAR access;			/* Access control - GMN03082005Ro */
	USHORT charset;			/* 0 - ASCII, 1 - EBCDIC */
	char devaddr[16+1];		/* Device Address */
	int  devport;			/* Device Port */
	USHORT  udp;			/* UDP protocol */
	USHORT  keepalive;		/* KEEP ALIVE option - GMN10112007Ro */
	int  tcp;				/* TCP protocol */
	int  tcpnoconnect;		/* TCP number of connections */
	char gateaddr[16+1];	/* Gateway Address */
	char netmask[16+1];		/* Network Mask */
	short int no_clients;	/* Current number of clients */
	client_t client[MAX_CLIENTS];	/* Max. 50 clients 09242003Ro */
	ULONG bufSize;		/* HSM INPUT/OUTPUT buffer size - GMN01292007Ro */
	UCHAR filler[16];
} racal_ch_t;

typedef	struct
{
	char devaddr[16+1];		/* Device Address */
	int  devport;			/* Device Port */
	char gateaddr[16+1];	/* Gateway Address */
	char netmask[16+1];		/* Network Mask */
	char dns[16+1];			/* Network DNS */
} racal_mg_t;


/* Host v.24 protocol configuration - GMN01042003Ro */
typedef	struct
{
	int  msghd_len;		/* Message Header Length 1-255 */
	USHORT trailer;		/* Message trailer - GMN01202005Ro */
	USHORT charset;		/* 0 - ASCII, 1 - EBCDIC */
	int  protocol;		/* Standard v.24 and Tranparent binary */
	unsigned char etx[2];	/* End of text for v.24 protocol */
	async_port_t port;	/* Parameters for v.24 */
	ULONG bufSize;		/* HSM INPUT/OUTPUT buffer size - GMN01292007Ro */
	UCHAR filler[16];
} racal_ch_v24_t;

/* GMN05142004 */
/*************************************************
typedef unsigned short int	USHORT;
typedef unsigned long int	ULONG;
typedef unsigned char		UCHAR;
**************************************************/

/* RACAL console port configuration */
typedef async_port_t racal_cc_t;

/* RACAL auxaliry port configuration */
typedef async_port_t racal_ca_t;

/* Defintion for the PIN words */
typedef struct
{
	int len;
	uchar pin_word[16+1];
} racal_pinwords_t;

#define	LEN_RSA_PAD	(sizeof(RSAKey)+32)

#ifndef	__HSM_NEW_CONFIG__

typedef	struct
{
	UCHAR  min_len;		/* Minimum HMAC verification length in bytes [5-20] */
	UCHAR  p11importexport; /* Enable PKCS#11 import and export for HMAC keys [Y/N] */
	UCHAR  x917importexport;/* Enable ANSI X9.17 import and export for HMAC keys [Y/N] */
} hmacConfig;

/* RACAL security configuration */
typedef	struct
{
	int  pinlen;		/* Range: 4 - 12 */
	USHORT echo;		/* Echo: oN or ofF */
	USHORT atalla;		/* Atalla ZMK variant support: N or F (oN or ofF) */
	USHORT transackey;	/* Racal or Australian Key : [R/A] */
	USHORT ic_version;	/* Number of version - PBOC */
	USHORT ic_index;	/* Number of index per version - PBOC */
	USHORT ic_group;	/* Number of group - PBOC */

	int  ustoreklen;	/* User storage key length(Single/Double/Triple) */
						/* 8 - S, 16 - D, 24 - T */
	int  kstoreklen;	/* Key storage key length(Single/Double/Triple) - GMN12092003Ro */
						/* 8 - S, 16 - D, 24 - T */
	USHORT lmk_erase;		/* Erase LMKs, confirm Y or N */
	UCHAR  encryptedDeciTable;	// Encrypted Decimalization Table - GMN12152005Ro
	UCHAR  checkDeciTable;	// Check Decimalization Table - GMN12202005Ro
	int  clearpin;		/* Select clear PIN: Y or N */
	int  zmk_translate;	/* Enable ZMK translate command: Y or N */
	int  x917_import;	/* Enable X9.17 for import: Y or N */
	int  x917_export;	/* Enable X9.17 for export: Y or N */
	int  sol_batch;		/* Solicitation batch size: a one to four-digit number, 1 to 2048(1535) 密码申请函批处理空间大小 */
	USHORT zmk_128;		/* Single/double ZMKs: S or D(Single or Double) */
	USHORT term_pin;	/* Enable terminal PIN encryption. - GMN05142004 */
	USHORT pin_algo;	/* PIN encryption algorithm: A or B(Visa method or Racal method) */
	USHORT extended_cv;	/* Output extended key check value - GMN08302004Ro */
	USHORT ic_hstcmd;	/* Host command version: HOSTCMD_IC_BCD, HOSTCMD_IC_HEX - PBOC */
	USHORT auth_mode;	/* Card/Password authorization: C or P(Card or Password) */
	int  no_auth_officer;	/* Number of authorization officer. (1 - 3) - GMN12102003Ro */
	char issuer_pass[9];	/* Card issuer password: 8 alphanumeric printable characters . (ENTER = nochange) */
	USHORT oldlmk;		/* Old LMK loaded to Key change storage */
	UCHAR icIGA;		/* IC key inter group access - GMN08072006Ro */
	UCHAR rsa_compat;	/* Thales RSA option keytype compatiable - GMN01162007Ro */
	hmacConfig  hmac_config;/* HMAC configuration - GMN08222008Ro */
	UCHAR filler[64];
} racal_cs_t;

typedef	struct
{
	uchar hsm_sn[16];		/* HSM serial number - GMN01042004Ro */
	ULONG func;				/* HSM hardware configuration - GMN01042004 */
	racal_cs_t rCs;			/* Security parameters defintion */
	racal_pinwords_t pin_words[10];	/* PIN words definition */
	racal_ch_t rCh;			/* Host port TCP/IP definition */
	racal_ch_v24_t rV24;	/* Host port v.24 protocol - GMN01042003Ro */
	racal_cc_t rCc;			/* Console port definition */
	racal_ca_t rCa;			/* Auxiliary port definition */
	racal_mg_t mAng;		/* B/S Host port TCP/IP definition */

	USHORT response_mode;	/* 1 - Response before printing */
							/* 2 - Response after printing */
	UCHAR  acc_spaces;		/* 0 - No spaces, 1 - with spaces between account numbers - GMN03272006Ro */
	UCHAR  print_pan_len;	/* default: 6-12 - GMN03282006Ro */
	UCHAR  language;		/* 0 - default ENGLISH, 1 - local */

	UCHAR  print_port;		/* 0 - Serial printer, 1 - Parallel printer, 2 - tcp/ip printer, 3 - usb printer */
//	UCHAR  tmk_idx;			/* TMK index for CMB CHINA - GMN1020200Ro */
//	UCHAR  edk_idx;			/* EDK index for CMB CHINA - GMN1020200Ro */
	cfgCMB_t cmb;			/* CMB China configuration - GMN1020200Ro */
	UCHAR  sb_ac;			/* SheBao AC: 0 - disable, 1 - enable */
	UCHAR  jk56_oldver;		/* Compatable version: 0 - new, 1 - old */
	UCHAR  jk56_msghdr;		/* Compatable version: 0 - no header, 1 - header */
	UCHAR  jk56_cmdlen;		/* Compatable version: 0 - no length bytes, 1 - length bytes */
	UCHAR  ic_x917_import;	/* ANSI X9.17 import - GMN11032006Ro */
	UCHAR  ic_x917_export;	/* ANSI X9.17 export - GMN11032006Ro */
	UCHAR  disable_jk_auth;	/* Disable JK 68, 2A, 31 authorization - GMN12132006Ro */
	UCHAR  disable_ic_auth;	/* Disable IC host command authorization - GMN01202007Ro */
	UCHAR  KBK_auth;		/* Added Using KBK command with condition - GMN01282007Ro */
	UCHAR filler[64];
} racal_cfg_t;

#else	/* __HSM_NEW_CONFIG__ */


typedef struct
{
	USHORT ic_version;	/* Number of version - PBOC */
	USHORT ic_index;	/* Number of index per version - PBOC */
	USHORT ic_group;	/* Number of group - PBOC */
	UCHAR  x917_import;	/* ANSI X9.17 import - GMN11032006Ro */
	UCHAR  x917_export;	/* ANSI X9.17 export - GMN11032006Ro */
	USHORT ic_hstcmd;	/* Host command version: HOSTCMD_IC_BCD, HOSTCMD_IC_HEX - PBOC */
	USHORT icIGA;		/* IC key inter group access - GMN08072006Ro */
} hsmIcConfig;

typedef struct
{
	cfgCMB_t cmb;		/* CMB China configuration - GMN1020200Ro */
	UCHAR  jk56_oldver;	/* Compatable version: 0 - new, 1 - old */
	UCHAR  jk56_msghdr;	/* Compatable version: 0 - no header, 1 - header */
	UCHAR  jk56_cmdlen;	/* Compatable version: 0 - no length bytes, 1 - length bytes */
} hsmJkConfig;

typedef	struct
{
	UCHAR  min_len;		/* Minimum HMAC verification length in bytes [5-20] */
	UCHAR  p11exportimport; /* Enable PKCS#11 import and export for HMAC keys [Y/N] */
	UCHAR  x917exportimport;/* Enable ANSI X9.17 import and export for HMAC keys [Y/N] */
} hmacConfig;

/* RACAL security configuration */
typedef	struct
{
	int  pinlen;		/* Range: 4 - 12 */
	USHORT echo;		/* Echo: oN or ofF */
	USHORT atalla;		/* Atalla ZMK variant support: N or F (oN or ofF) */
	USHORT transackey;	/* Racal or Australian Key : [R/A] */

	int  ustoreklen;	/* User storage key length(Single/Double/Triple) */
				/* 8 - S, 16 - D, 24 - T */
	int  kstoreklen;	/* Key storage key length(Single/Double/Triple) - GMN12092003Ro */
				/* 8 - S, 16 - D, 24 - T */
	USHORT  lmk_erase;		/* Erase LMKs, confirm Y or N */
	int  clearpin;		/* Select clear PIN: Y or N */
	int  zmk_translate;	/* Enable ZMK translate command: Y or N */
	int  x917_import;	/* Enable X9.17 for import: Y or N */
	int  x917_export;	/* Enable X9.17 for export: Y or N */
	int  sol_batch;		/* Solicitation batch size: a one to four-digit number, 1 to 2048(1535) */
	USHORT zmk_128;		/* Single/double ZMKs: S or D(Single or Double) */
	USHORT term_pin;	/* Enable terminal PIN encryption. - GMN05142004 */
	USHORT pin_algo;	/* PIN encryption algorithm: A or B(Visa method or Racal method) */
	USHORT extended_cv;	/* Output extended key check value - GMN08302004Ro */
	USHORT auth_mode;	/* Card/Password authorization: C or P(Card or Password) */
	USHORT no_auth_officer;	/* Number of authorization officer. (1 - 3) - GMN12102003Ro */
	char issuer_pass[9];	/* Card issuer password: 8 alphanumeric printable characters . (ENTER = nochange) */
	USHORT oldlmk;		/* Old LMK loaded to Key change storage */
	UCHAR  encryptedDeciTable;	// Encrypted Decimalization Table - GMN12152005Ro
	UCHAR  checkDeciTable;	// Check Decimalization Table - GMN12202005Ro
	hsmIcConfig ic_config;	/* IC configuration */
//	hmacConfig  hmac_config;/* HMAC configuration - GMN08222008Ro */
} racal_cs_t;

typedef	struct
{
	uchar hsm_sn[16];	/* HSM serial number - GMN01042004Ro */
	ULONG func;		/* HSM hardware configuration - GMN01042004 */
	racal_cc_t rCc;		/* Console port definition */
	racal_ca_t rCa;		/* Auxiliary port definition */
	racal_pinwords_t pin_words[10];	/* PIN words definition */
	racal_cs_t rCs;		/* Security parameters defintion */
	racal_ch_t rCh;		/* Host port TCP/IP definition */
	racal_ch_v24_t rV24;	/* Host port v.24 protocol - GMN01042003Ro */
	USHORT response_mode;	/* 1 - Response before printing */
				/* 2 - Response after printing */
	UCHAR  acc_spaces;	/* 0 - No spaces, 1 - with spaces between account numbers - GMN03272006Ro */
	UCHAR  print_pan_len;	/* default: 6-12 - GMN03282006Ro */
	UCHAR  language;	/* 0 - default ENGLISH, 1 - local */

	UCHAR  print_port;	/* 0 - Serial printer, 1 - Parallel printer */
	hsmJkConfig jk_config;	/* JK configuration - GMN11032006Ro */
	UCHAR  sb_ac;		/* SheBao AC: 0 - disable, 1 - enable */
} racal_cfg_t;

#endif	/* __HSM_NEW_CONFIG__ */

/* PIN mailer & Key document mailer defintions */
typedef struct
{
	int  len;
	uchar field[LEN_MAX_LINE+1];
} print_field_t;

typedef struct
{
	print_field_t key;
	print_field_t cv;
} clear_key_t;

typedef struct
{
	print_field_t pin;
	print_field_t pan;
	print_field_t refno;
} clear_pin_t;

typedef struct
{
	int fld_no;	/* 0-1F: Save the 1st mailer field */

	union
	{
		clear_key_t key;
		clear_pin_t one_up;
	} one_up;
	clear_pin_t two_up;
	clear_key_t keyA;
	clear_key_t keyB;
	clear_key_t keyC;
	clear_key_t keyD;
	print_field_t print_field[MAX_PM_FIELD];
	int print_flag;	/* 0: Not print; 1 - Print */
} pin_mailer_t;

typedef struct
{
	byte Method;
	byte Algo;
	byte genMode;
	byte timeOut;
	byte Mask;
	char lmkSchem;
	byte noPerson;
	byte kLen;
	char kType[3];
	char cKey[48];
	char eKey[48];
	char Cv[16];
	char Prompt[100+1];
} PROMPT_t;

/* Shared memory structure for RACAL */
struct hsmShmStr
{
	int authorized;			/* 1 - Authorized, 0 - Not Authorized */
	int hsm_state;			/* 1 - HSM online, 0 - HSM offline */
	int hsm_armed;			/* 1 - HSM is armed, 0 - HSM is in normal state - GMN04222004Ro */
	int dual_auth;			/* AUTHORIZED - Dual Authorization, NOT_AUTHORIZED - Disable Dual Authorization */
	int printer_opened;		/* 1 - Printer opend, 0 - Printer not opened. GMN20040214Ro */
	racal_cfg_t hsmcfg;		/* Configuration file */
	UCHAR LMKs[MAX_LMKS][LEN_LMK];	/* Current LMKs */
	UCHAR oldLMKs[MAX_LMKS][LEN_LMK];	/* Key Change Storage */
#ifndef	__NO_JKIC__
#ifndef	__NO_IC__
	UCHAR kstore[LEN_KEYSTORE];	/* Key storage : 10312003Ro */
#ifdef	__IC_DATA_DEF__
	UCHAR *icData;			/* Index for IC application data - GMN12242008Ro */
#endif
#endif	/* __NO_IC__ */
#endif	/* __NO_JKIC__ */
	UCHAR ustore[LEN_USERSTORE];	/* User Storage 该区间数据不存放在加密卡上 */
	UCHAR prtform[LEN_PRTFORM];	/* Print form storage */

	//2017/5/26 JK密钥和SM4密钥、SM2协商密钥使用同一个存储区，各密钥混存
	UCHAR jkstore[LEN_JKSTORE];	/* JK key storage - GMN07252004Ro */

//	UCHAR ShareMemRsaKey[MAX_RSAKEY*10*LEN_RSA_PAD];	/* Max. no of RSA key */
	UCHAR ShareMemRsaKey[MAX_RSAKEY*LEN_RSA_PAD];		/* Max. no of RSA key */
	UCHAR ShareMemSm2Key[MAX_SM2KEY*sizeof(SM2Key)];	/* Max. no of SM2 key 2017/5/17 add*/
	pin_mailer_t pm;		/* PIN mailer or key mailer */
	uchar rnd_seed[8];		/* Pseudo-random number seed */
#ifdef	__HSM_SHEBAO__
	UCHAR  d_key[24];		/* Diversification key */
	UCHAR  s_key[24];		/* Session key */
#endif
	USHORT upd_authed;		/* 0 - Update Prohibited, 1 - Update Permitted
					   Program Update Flag: 05252003Ro */
	/* LEN_USERSTORE/HsmShm.rCs.ustoreklen */
	USHORT max_usrstore_idx;

#ifndef	__NO_JKIC__
#ifndef	__NO_IC__
	termIndex_t termKeyIndex;	/* Term ID and JK key index - GMN10202006Ro */
	/* LEN_KEYSTORE/HsmShm.rCs.ustoreklen - NEW10312003Ro */
	USHORT max_keystore_idx;
	ULONG ic_count;			/* IC Issue card count - GMN03152009Ro */
#endif	/* __NO_IC__ */
#endif	/* __NO_JKIC__ */

	int   pid_mgr;			/* Process ID - gmnmon : 04212004Ro */
	int   pid_tcp;			/* Process ID - gmntcp : 09142003Ro */
	int   pid_tcp_nh;		/* Process ID - gmntcp_nh : 08282004Ro */
	int   pid_v24;			/* Process ID - gmnv24 : 09142003Ro */
	int   pid_sna;			/* Process ID - gmnsna : 09142003Ro */
	int   pid_x25;			/* Process ID - gmnx25 : 09142003Ro */

	char  sense_byte;		/* Crypto card sense byte - GMN05082004 */
	int   thread_no;		/* Current connected thread number. GMN01082003Ro */
	int   thread_no_2;		/* Current connected thread number. GMN02242005Ro */
	int   wkey_mode;		/* IC & PBOC key writing mode - buffer or store. GMN08022004Ro */
	ULONG afw;				/* Application fuctionality word - GMN08082004Ro */
	int   fips;				/* FIPS test mode: 0 - off, 1 - on. GMN01262007Ro */
	int   console_fd;		/* CONSOLE file descriptor - GMN05032008Ro */
	PROMPT_t prompt;		/* Exchange area between Console and Server - GMN03232009Ro */

	char passwd[8];			//备份及恢复密码
	int   hmode;			//1:备份 2：恢复
	int   myType;			//密钥类型1-对称(1-128)	2-SM2(1-100)
	int   rcCode;			//返回结果
	int   webCode;			//heng.z web service
	char  webInfo[4096];	//heng.z web info
	int	  method;			//heng.z web method
	char  z_time[6];        //heng.z time
	char  z_date[6];		//heng.z date
	char  z_flag[16];       //heng.z card flag
	char  z_h_flag[16];		//heng.z card flag2
	char oldpasswd[16];    	//old passwd

} *phsmShm;

#endif	/* end of __RACAL_HSM_H__ */
