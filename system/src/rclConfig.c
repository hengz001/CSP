#include "mgrSvr.h"

int CheckHsmFunc(unsigned long func)
{
	ULONG pfunc = phsmShm->hsmcfg.func;
	return(pfunc&func);
}

void SetHsmFaultIndicator(int onoff){
	int dev_NVRAM;
	int OnOff = onoff;

	dev_NVRAM = open("/dev/kstore1",O_RDWR);
	if(dev_NVRAM == -1){
		return;
	}
	ioctl(dev_NVRAM,CARD_FAULTINDICATOR,&OnOff);
	close(dev_NVRAM);
}

void ResetUsrStore (void)
{
	memset(phsmShm->ustore,0,sizeof(phsmShm->ustore));
}

void ResetPrtFormStore(void)
{
	memset(phsmShm->prtform,0,sizeof(phsmShm->prtform));
}

/* Get max. user storage index length */
int HsmGetMaxUsrStoreIdxLen ( void )
{
	// GMN11032006Ro 用户密钥长度
	switch( phsmShm->hsmcfg.rCs.ustoreklen )
	{
		case KSCHEM_SINGLE:
		case KSCHEM_DOUBLE:
		case KSCHEM_TRIPLE:
			break;
		default:
			phsmShm->hsmcfg.rCs.ustoreklen = KSCHEM_SINGLE;
			break;
	}
	/* Get Max. User Storage Index Length */
	return (LEN_USERSTORE / phsmShm->hsmcfg.rCs.ustoreklen );
}

/* Get max. key storage index length */
int HsmGetMaxKeyStoreIdxLen ( void )
{
	// GMN11032006Ro
	switch( phsmShm->hsmcfg.rCs.kstoreklen )
	{
		case KSCHEM_SINGLE:
		case KSCHEM_DOUBLE:
		case KSCHEM_TRIPLE:
			break;
		default:
			phsmShm->hsmcfg.rCs.kstoreklen = KSCHEM_SINGLE;
			break;
	}
	/* Get Max. User Storage Index Length - fixed bug from ustoreklen to kstoreklen GMN04052004Ro */
	return (LEN_KEYSTORE / phsmShm->hsmcfg.rCs.kstoreklen );
}

/*
 * 从加密机读IC卡密钥
 */
int ReadKeysFromKStore ( void )
{
	UCHAR group, version, index;
	UCHAR G = HsmGetIcGroup(), V = HsmGetIcVersion(), I = HsmGetIcIndex(), iG;
	int   rc;

	if (G==0 || V==0 || I==0){
		return -1;
	}

	//计算可存储的最大group
	if((iG = 65536 / ((V+1)*I*LEN_KEY_RECORD)) != G) G = iG;


	for(group=0; group<G; group++)
	{
		for(version=0; version<=V; version++)
		{
			for(index=0; index<I; index++)
			{
				rc = _readICindex(group, version, index, &phsmShm->kstore[HsmIcGetIndexFromGVI(group, version, index)], LEN_KEY_RECORD);
			}
		}
	}
	return 0;
}

/* Set current dual authorization state */
void HsmSetDualAuth (int state)
{
	/* HSM authorization state */
	switch (state)
	{
	case NOT_AUTHORIZED:
	case AUTHORIZED:
		phsmShm->dual_auth = state;
		break;
	default:
		break;
	}
	return;
}

/* Configure HSM authorization state */
void HsmSetAuthState (int state)
{
	/* HSM authorization state */
	switch (state)
	{
	case NOT_AUTHORIZED:
	case AUTHORIZED:
		phsmShm->authorized = state;
		break;
	default:
		break;
	}
	return;
}

void SetupHsmDefaultParm(void)
{
	//检测LMKs
	CheckLMKsParity();

	//检测oldLMKs
	CheckOldLMKsParity();

	/* Clear User data storage */
	ResetUsrStore ();

	/* Clear Print Format Data */
	ResetPrtFormStore();

	/* Get Max. User Storage Index Length */
	phsmShm->max_usrstore_idx = HsmGetMaxUsrStoreIdxLen ();

	/* Get Max. Key Storage Index Length - NEW10312003Ro */
	phsmShm->max_keystore_idx = HsmGetMaxKeyStoreIdxLen ();

	/* READ KEYS FROM KEY STORAGE for IC card */
	ReadKeysFromKStore ();

	//read RSA key
	if(CheckHsmFunc(SUPPORT_RACAL))
	{
		ReadRsaKeysFromCard();
	}

	//read SM2 key
	ReadSm2KeysFromCard();

	//read SM4 key
	ReadSm4KeysFromCard();

	//random
	DesRandomData(phsmShm->rnd_seed,sizeof(phsmShm->rnd_seed));

	//
	/* Read RSA key set from card to shared memory depending on HSM configuration */
	if( CheckHsmFunc ( SUPPORT_RSA) || CheckHsmFunc ( SUPPORT_DATACARD) )
	{
		//
	}

	//
	phsmShm->printer_opened = 0;
	phsmShm->wkey_mode = 1;
	phsmShm->afw = phsmShm->hsmcfg.func;
	phsmShm->hsm_armed = HSM_STATE_NORMAL;
	phsmShm->fips = 0;
	HsmSetDualAuth ( NOT_AUTHORIZED );
	HsmSetAuthState ( NOT_AUTHORIZED );
	HsmSetOnLine ();
	return ;
}

void ResetApiFunc (unsigned long func)
{
	unsigned long tmpfunc;

	tmpfunc = 0xFFFFFFFFL ^ func;
	phsmShm->afw &= tmpfunc;
}

void SetApiFunc (unsigned long func)
{
	phsmShm->afw |= func;
}

int HsmSetCryptoAlgo(void)
{
	int handle ;
	handle = GmnOpenSM2Card();
	if(handle < 0){
		ResetApiFunc(handle);
	}else{
		SetApiFunc(handle);
	}
	GmnCloseCard(handle);

	handle = GmnOpenCard();
	return 0;
}

int HsmGetLanguage(void)
{
	return phsmShm->hsmcfg.language == 1;
}

int isHsmOnLine(void)
{
	return phsmShm->hsm_state == HSM_ONLINE;
}

/* Check HSM if it's in Dual Authorization state */
int isHsmDualAuthorized(void)
{
	return phsmShm->dual_auth == AUTHORIZED;
}

/* Check the current HSM state if it's in Authorized state */
int isHsmAuthorized ( void )
{
	return (phsmShm->authorized == AUTHORIZED);
}

int isHsmArmed ( void )
{
	return phsmShm->hsm_armed == HSM_STATE_ARMED;
}

int HsmGetPrinterPort(void)
{
	return phsmShm->hsmcfg.print_port;
}

/* Set Current TCP Thread number */
void HsmSetCurrentThreadNum ( int no )
{
	if(no>=0)	phsmShm->thread_no = no;
}

/* Set the current HSM state to OFFLINE */
void HsmSetOffLine( void )
{
	phsmShm->hsm_state = HSM_OFFLINE;
}

int GetIfcfgFileIpAddr(int mode, char *ip)
{
	FILE *fp;
	char tmpbuf[255], *strtmp;
	char ifcfgeth[] = "/etc/sysconfig/network-scripts/ifcfg-eth0";

	if(mode == 0){
		ifcfgeth[strlen(ifcfgeth)-1] = '0';
	}else{
		ifcfgeth[strlen(ifcfgeth)-1] = '1';
	}

	fp = fopen(ifcfgeth,"r");
	if(fp==NULL) return 0;
	*ip = 0;
	while(fgets(tmpbuf,sizeof(tmpbuf),fp)){
		if(strstr(tmpbuf,"IPADDR")!=NULL)
		{
			strtmp = strstr(tmpbuf,"=");
			strtmp++;
			while(*strtmp==' ')	strtmp++;
			strcpy(ip,strtmp);
			break;
		}
	}
	fclose(fp);
	return 0;
}

char *HsmGetDeviceAddress(void)
{
	static char ip[16+1];
	memset(ip,0,sizeof(ip));
	if(strlen(phsmShm->hsmcfg.rCh.devaddr)<17){
		strcpy(ip,phsmShm->hsmcfg.rCh.devaddr);
	}
	if(ip[0]==0||HsmCheckIpSyntax(ip))
	{
		GetIfcfgFileIpAddr(0,ip);
		if(ip[0]==0){
			strcpy(ip,"192.168.1.100");
		}else{
			strcpy(phsmShm->hsmcfg.rCh.devaddr,ip);
		}
	}
	return ip;
}


char *HsmGetNetMask(void)
{
	static char mask[16+1];
	memset(mask,0,sizeof(mask));
	if(phsmShm->hsmcfg.rCh.netmask[0] && strlen(phsmShm->hsmcfg.rCh.netmask)<17)
	{
		strcpy(mask,phsmShm->hsmcfg.rCh.netmask);
	}
	if(HsmCheckIpSyntax(mask)){
		strcpy(mask,"255.255.255.0");
	}
	return mask;
}


char *HsmGetNetBroadcast(void)
{
	static char ip[16+1];
	char *p;
	strcpy(ip,HsmGetDeviceAddress());
	p = strrchr(ip,'.');
	if(p==NULL) return NULL;
	strcpy(p+1,"255");
	return ip;
}

char *HsmGetGatewayAddress(void)
{
	static char ip[16+1];

	memset(ip,0,sizeof(ip));
	if(phsmShm->hsmcfg.rCh.gateaddr[0] && strlen(phsmShm->hsmcfg.rCh.gateaddr) < 17)
	{
		strcpy(ip, phsmShm->hsmcfg.rCh.gateaddr);
	}
	if(ip[0]==0 || HsmCheckIpSyntax(ip))
	{
		/* Default gateway address */
		strcpy(ip,"192.168.1.1");
	}
	return ip;
}

void HsmSetOnLine(void)
{
	phsmShm->hsm_state = HSM_ONLINE;
}

int HsmGetMaxTcpConnectNo(void)
{
	return phsmShm->hsmcfg.rCh.tcpnoconnect? phsmShm->hsmcfg.rCh.tcpnoconnect:1024;
}

/* Get TCP keepalive timer - GMN10112007Ro */
int HsmTcpGetKeepaliveTimer( void )
{
	int  len = phsmShm->hsmcfg.rCh.keepalive;

	if(len>0&&len<121)
	{
		return len;
	}
	return 60;
}

/**
 * 客户端访问控制
 */
int hsmTcpAllowAccessControl( void )
{
	return (phsmShm->hsmcfg.rCh.access == HSM_ALLOWED);
}

/* Get Current TCP Thread number */
int HsmGetCurrentThreadNum ( void )
{
	return phsmShm->thread_no;
}

// Get HSM Max. TCP buffer size
long HsmGetTcpBufSize( void )
{
	return phsmShm->hsmcfg.rCh.bufSize?phsmShm->hsmcfg.rCh.bufSize:4096*2;
}

/* Get current message header length on TCP protocol */
int HsmTcpGetMsgHdrLen ( void )
{
	int len = phsmShm->hsmcfg.rCh.msghd_len;
	if(len>=0&&len<=255)
	{
		return len;
	}
	return 0;
}

/* Get character set for TCP protocol */
int HsmTcpGetCharSet ( void )
{
	int  charset = phsmShm->hsmcfg.rCh.charset;
	switch ( charset )
	{
	case CHARSET_ASCII:
	case CHARSET_EBCDIC:
	case CHARSET_IBM1388:
		break;
	default:
		charset = CHARSET_ASCII;
		break;
	}
	return charset;
}

int hsmTcpTailerSupported( void )
{
	return (phsmShm->hsmcfg.rCh.trailer == HSM_ALLOWED);
}

/*
 * 复制文件
 */
int copyFile(char *srcFile, char *destFile)
{
	int rc = 0, pos, filesize;
	char *buff = NULL;
	FILE *sfp = fopen(srcFile, "r");
	FILE *dfp = fopen(destFile, "w+");

	if (sfp == NULL || dfp == NULL) {
		rc = -1;
		goto err_exit;
	}

	//分配缓存
	if ((buff = malloc(1024)) == NULL) {
		rc = -1;
		goto err_exit;
	}

	//读数据
	filesize = fread(buff, sizeof(char), 1024, sfp);

	//写数据
	if (filesize > 0) {
		pos = fwrite(buff, sizeof(char), filesize, dfp);
	}

err_exit:
	if (sfp != NULL)	fclose(sfp);
	if (dfp != NULL)	fclose(dfp);
	if (buff != NULL)	free(buff);

	return rc;
}

int HsmGetDevicePort ( void )
{
	/* Default TCP port */
	return phsmShm->hsmcfg.rCh.devport;
}
