#ifndef	__HSM_DEFS__
#define	__HSM_DEFS__


#ifdef	WIN32
#define	LEN_MAX_FNAME	_MAX_FNAME	/* Win32 */
#define	LEN_MAX_PATH	MAX_PATH	/* Win32 */
#else
#define	LEN_MAX_FNAME	FILENAME_MAX	/* SCO Unix */
#define	LEN_MAX_PATH	MAX_PATH	/* SCO Unix */

typedef	long	HANDLE;
typedef	long	DWORD;


/*	Type Defintions			*/

/*	End of Type Definitions		*/


#endif
typedef long		HSM_DEV;


#define STX		0x02	/* Start of Sentinal */
#define ETX		0x03	/* End of Sentinal */

#define SEND_TIMEOUT	60	
#define RECV_TIMEOUT	90	


#define DEFAULT_E_PIN_LEN 16
#define MAX_MSGDATA     4096
#define LEN_MAX_BLOCK 2048


#define CHAIN_TIMEOUT 0

#define	MAX_LOG_SIZE	(2048*1024)



#define ALGO_DESTDES            0
#define ALGO_SSF33              1
#define ALGO_SSF10              2
#define ALGO_SCB2               3
#define ALGO_AES                4
#define ALGO_SM4                5


#define HASH_MD2        0
#define HASH_SHA1       1
#define HASH_MD5        2
#define HASH_ISO10118_2 3
#define HASH_NOHASH     4
#define HASH_SHA224     5
#define HASH_SHA256     6
#define HASH_SHA384     7
#define HASH_SHA512     8
#define HASH_MD4        9
#define HASH_RIPEMD128  10
#define HASH_RIPEMD160  11
#define HASH_RIPEMD256  12
#define HASH_RIPEMD320  13
#define HASH_SM3  14

#define SM3_DIGEST_LENGTH 32

#define SIG_ALGO_RSA    1
#define SIG_ALGO_ECC    2
#define SIG_ALGO_SM2    3

#define IV_LEN   8
#define S_LEN   8
#define D_LEN   (2*S_LEN)
#define T_LEN   (3*S_LEN)

#define i_k_LEN 4
#define I_K_LEN 3



#define ZMK        400
#define KEY        ZMK
#define ZPK        600
#define PINKEY     ZPK
#define ZAK        2600
#define MACKEY     ZAK
#define ZEK        3000
#define ENCKEY     ZEK
#define SESSIONKEY 2400
#define DEVIATIONKEY 5000


#define ZMK_TYPE        "00A"
#define ZPK_TYPE        "001"
#define TPK_TYPE        "002"
#define TAK_TYPE        "003"
#define ZAK_TYPE        "008"
#define ZEK_TYPE        "00A"

/*	Error Code Definitions		*/

#define	HSM_ERROR		(-1)
#define	HSM_OK			0
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


#define CONFIGFILE "GMNCSP.CONFIG"
#define LOGFILE "GMNCSP.LOG"

/*	End of Error Code Definitions	*/
#endif /* __HSM_DEFS__ */

