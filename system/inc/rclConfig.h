
void SetHsmFaultIndicator(int onoff);

void SetupHsmDefaultParm(void);

int HsmSetCryptoAlgo(void);

int HsmGetLanguage(void);

int isHsmOnLine(void);

int isHsmDualAuthorized(void);

int isHsmAuthorized ( void );

int isHsmArmed ( void );

int HsmGetPrinterPort(void);

int CheckHsmFunc(unsigned long func);

void HsmSetCurrentThreadNum ( int no );

void HsmSetOffLine( void );

char *HsmGetDeviceAddress(void);

int GetIfcfgFileIpAddr(int mode, char *ip);

char *HsmGetNetMask(void);

char *HsmGetNetBroadcast(void);

char *HsmGetGatewayAddress(void);

void HsmSetOnLine(void);

int HsmGetMaxTcpConnectNo(void);

/* Get TCP keepalive timer - GMN10112007Ro */
int HsmTcpGetKeepaliveTimer( void );

int hsmTcpAllowAccessControl( void );

/* Get Current TCP Thread number */
int HsmGetCurrentThreadNum ( void );

// Get HSM Max. TCP buffer size
long HsmGetTcpBufSize( void );

/* Get current message header length on TCP protocol */
int HsmTcpGetMsgHdrLen ( void );

int HsmTcpGetCharSet ( void );

int hsmTcpTailerSupported( void );

int copyFile(char *srcFile, char *destFile);

int HsmGetDevicePort ( void );

int isHsmEchoOn ( void );
