#include "mgrSvr.h"

//static int debug = 0;
static int debug = 1;

int fd;
char prompt[32];

void sig_hsm_interrupt(int iSignal);

void SetupPrompt(char *buf);

int CheckHsmArmState(void);

typedef int (*function)(int fd1, int *display);

typedef struct {
	char cmd_code[6];
	function cmd;
	int checkauth;
	int state;
} racalFunc_t;

static racalFunc_t hsm_cmd[] = {
		{ "A", 	AA,		0, 0 },
		{ "B", 	AA,		1, 0 },
		{ "C", 	AA,		0, 1 },
		{ "UP", UP,		0, 0 },
		{ "", 	NULL,	0, 0 }
};

int main(int argc, char **argv) {
	struct rlimit limit;
	int len, rc = 0;
	char buf[2048];
	int display, not_allowed;
	racalFunc_t *cmdp = NULL;

	//设置系统资源限制
	limit.rlim_max = 10240;
	limit.rlim_cur = 10240;
	setrlimit(RLIMIT_NOFILE, &limit);

	//读取配置卡
	ReadConfigAndSaveTOCard();

	//开启守护进程
	hsmDaemon(debug);

	//开辟内存空间
	if ((attachShm()) < 0) {
		SetHsmFaultIndicator(FAULT_INDICATOR_ON);
		exit(-1);
	}

	//save process id in shared memory
	phsmShm->pid_mgr = getpid();

	//读取配置
	ReadHsmDefaultParm();

	//读取keys
	ReadKeysFromCard();

	//取消升级状态
	HsmResetUpdateFlag();

	//设置参数
	SetupHsmDefaultParm();

	//检查加密机卡
	HsmSetCryptoAlgo();

	//开启TCP/IP
	if(CheckHsmFunc (PROTOCOL_TCP)){
		StartTcpMainProcess();
	}

// signal 屏蔽各种中断

	//初始化端口
	if ((fd = OpenConsolePort()) < 0) {
		SetHsmFaultIndicator(FAULT_INDICATOR_ON);
		exit(-1);
	}

	//保存串口fd
	phsmShm->console_fd = fd;

	//开启中断 显示
	signal(SIG_HSM_INTERRUPT, sig_hsm_interrupt);

	//开启监控进程
	StartMonMainProcess();

	while (1) {
		//检测LMK
//		if (0)
		if( !(CheckLMKsParity()) )
		{
			SetHsmFaultIndicator(FAULT_INDICATOR_ON);
		} else {
			SetHsmFaultIndicator(FAULT_INDICATOR_OFF);
		}
		//设置联机状态
		SetupPrompt(prompt);

		//发送指令
		len = WriteLine(fd, prompt, prompt);
		if (len < 0) {
			ClearPort(fd);
		}

		//接收指令
		len = ReadLine(fd, buf, sizeof(buf));
		if (len < 0) {
			ClearPort(fd);
		}

		//
		WriteNewLine(fd);
		strupper(buf);
		if (len > 0) {
			display = 0;
			not_allowed = 0;
			for (cmdp = hsm_cmd; cmdp->cmd != NULL; cmdp++) {
				int ilen;
				ilen = MAX(len, strlen(cmdp->cmd_code));
				if (!memcmp(buf, cmdp->cmd_code, ilen)) {
					if (cmdp->checkauth && !isHsmAuthorized()) {
						WriteLine(fd, "系统未进入授权状态\n\r", "NOT AUTHORIZED\n\r");
						not_allowed = 1;
						break;
					}
					if (cmdp->state && isHsmOnLine()) {
						WriteLine(fd, "命令不允许执行!\n\r",
								"Function not allowed!\n\r");
						not_allowed = 1;
						break;
					}
					rc = (*cmdp->cmd)(fd, &display);
					break;
				}
			}
			if (not_allowed) {
				continue;
			}
			if (rc < 0) {
				WriteLine(fd, "命令执行中断!", "Function interrupted!");
				WriteNewLine(fd);
				continue;
			}
			if (NULL == cmdp->cmd) {
				WriteLine(fd, "命令输入错误!\n\r", "Function unknown!\r\n");
			}

			if (display) {
				if (rc > 0) {
					WriteLine(fd, "命令执行错误!\n\r", "Function failed!\r\n");
				} else {
					WriteLine(fd, "命令执行正确!\n\r", "Function completed!\r\n");
				}
				WriteNewLine(fd);
			}
		}
	}

	return 0;
}

void sig_hsm_interrupt(int iSignal) {
	signal(SIG_HSM_INTERRUPT, SIG_IGN);

	switch (phsmShm->sense_byte) {
	case HSM_STATE_OFFLINE:
		if (CheckHsmFunc(PROTOCOL_TCP)) {
			if (phsmShm->pid_tcp > 0) {
				kill(phsmShm->pid_tcp, SIG_THREADKILL);
			}
			if ((CheckHsmFunc(PROTOCOL_TCP_NH))
					&& !(CheckHsmFunc(PROTOCOL_TCP_WL))) {
				if (phsmShm->pid_tcp_nh > 0)
					kill(phsmShm->pid_tcp_nh, SIG_THREADKILL);
			}
			HsmSetCurrentThreadNum(0);
		}
		if (CheckHsmFunc(PROTOCOL_V24)) {
			;
		}
		HsmSetOffLine();
		break;
	case HSM_STATE_ARMED:
		phsmShm->hsm_armed = HSM_STATE_ARMED;
		break;
	case HSM_STATE_NORMAL:
		phsmShm->hsm_armed = HSM_STATE_NORMAL;
		break;
	}

	SetupPrompt(prompt);
	WriteLine(fd, prompt, prompt);
	signal(SIG_HSM_INTERRUPT, sig_hsm_interrupt);
}

void SetupPrompt(char *buf) {
	int lang = HsmGetLanguage();

	CheckHsmArmState();

	if (isHsmOnLine()) {
		(lang) ? strcpy(buf, "联机") : strcpy(buf, "OnLine");
	} else {
		(lang) ? strcpy(buf, "脱机") : strcpy(buf, "OffLine");
	}
	if (isHsmDualAuthorized()) {
		(lang) ? strcat(buf, "双重") : strcat(buf, "-DUAL");
	}
	if (isHsmAuthorized()) {
		(lang) ? strcat(buf, "授权") : strcat(buf, "-AUTH");
	}
	if (isHsmArmed()) {
		(lang) ? strcat(buf, "[警戒]") : strcat(buf, "[ARMED]");
	}
	strcat(buf, ">");

	return;
}

int CheckHsmArmState(void) {
	int dev_RAM;
	UINT status = 0;

	dev_RAM = open("/dev/kstore1", O_RDWR);
	if (dev_RAM == -1) {
		return -1;
	}
	ioctl(dev_RAM,CARD_ALERT,&status);

	if (status) {
		phsmShm->hsm_armed = HSM_STATE_ARMED;
	} else {
		phsmShm->hsm_armed = HSM_STATE_NORMAL;
	}
	close(dev_RAM);
	return (phsmShm->hsm_armed);
}

