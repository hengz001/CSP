#include "mgrSvr.h"

int VerifyManageCard(int fd, int update) {
//	int icdev;
//	char buf[1024];
//	char resp[80];
//	icInfo_t icInfo;
//	char pin[16];
//	int len = 16;
//
//	if ((icdev = IcOpenDevice()) < 0) {
//		return (FALSE);
//	}
//	WriteLine(fd, "插入智能卡准备好后按回车键:", "Insert Card and press ENTER when read:");
//	ReadPromptMessage(fd, buf);
//
//	if (ResetCardDevice(fd, icdev) < 0) {
//		IcCloseDevice(icdev);
//		return (FALSE);
//	}
//
//	if ((IcReadIdentity(icdev, &icInfo, resp)) < 0) {
//		WriteLine(fd, "插入的卡不可识别或卡未格式化.",
//				"NOT AN IDENTIFIED CARD OR CARD NOT FORMATTED.");
//		WriteNewLine(fd);
//		dv_beep(icdev, LONG_BEEP);
//		IcCloseDevice(icdev);
//		return (FALSE);
//	}
//
//	switch (icInfo.usage_id) {
//	case IC_CARD_MGR:
//		break;
//	case IC_CARD_UPDATE:
//		if (!update) {
//			WriteLine(fd, "插入的卡不是管理卡.", "NOT A MANAGEMENT CARD.");
//			WriteNewLine(fd);
//			dv_beep(icdev, LONG_BEEP);
//			IcCloseDevice(icdev);
//			return (FALSE);
//		}
//		break;
//	case IC_CARD_TEST:
//	case IC_CARD_LMK:
//	case IC_CARD_AUTH:
//	case IC_CARD_ZMK:
//	case IC_CARD_DATA:
//	case IC_CARD_DATA_JK:
//	case IC_CARD_DATA_IC:
//	case IC_CARD_DATA_STK:
//	default:
//		WriteLine(fd, "插入的卡不是管理卡或卡未格式化.",
//				"NOT A MANAGEMENT CARD OR CARD NOT FORMATTED.");
//		WriteNewLine(fd);
//		dv_beep(icdev, LONG_BEEP);
//		IcCloseDevice(icdev);
//		return (FALSE);
//	}
//	memset(pin, 0, sizeof(pin));
//
//	if ((EnterSmartCardPin(fd, icdev, pin, &len, resp)) < 0) {
//		IcCloseDevice(icdev);
//		return (FALSE);
//	}
//
//	/* Enter management passwd */
//	len = getpasswd(fd, "请输入管理员口令: ", "Enter management password: ", buf, echo);
//
//	if (len < 0) {
//		WriteLine(fd, "出现未知错误.", "UNKNOWN ERROR.");
//		dv_beep(icdev, LONG_BEEP);
//		IcCloseDevice(icdev);
//		return (FALSE);
//	}
//
//	/* Check management card password */
//	if (IcCheckMgrKey(icdev, pin, buf, &len, resp) < 0) {
//		WriteLine(fd, "读管理卡出现错误.", "MANAGEMENT CARD READ ERROR.");
//		dv_beep(icdev, LONG_BEEP);
//		IcCloseDevice(icdev);
//		return (FALSE);
//	}
//
//	WriteNewLine(fd);
//	dv_beep(icdev, SHORT_BEEP);
//	//******************************************
//	IcCloseDevice(icdev);
	return TRUE;
}

/*
 * 启动更新进程
 */
static void hsmUpdate ( void )
{
	char path[256];
	getcwd(path,sizeof(path));
	strcpy(path+strlen(path),"/");
	strcpy(path+strlen(path),"gmnupd");
	execl(path, "gmnupd", NULL);
}

int UP(int fd, int *display) {
	if (VerifyManageCard(fd,1)) {
		HsmSetUpdateAuth(TRUE);

		/* Kill HSM main process and child process 中止TCP进程 */
		if(CheckHsmFunc(PROTOCOL_TCP))
		{
			if (phsmShm->pid_tcp > 0)
				kill(phsmShm->pid_tcp, SIGUSR2);
		}

		/* TCP/IP no header version - GMN08282004Ro */
		if(CheckHsmFunc(PROTOCOL_TCP_NH))
		{
			if (phsmShm->pid_tcp_nh > 0)
				kill(phsmShm->pid_tcp_nh, SIGUSR2);
		}

		if(CheckHsmFunc(PROTOCOL_V24))
		{
			if (phsmShm->pid_v24 > 0)
				kill(phsmShm->pid_v24, SIGUSR2);
		}
		sleep(5);

		WriteLine(fd,"密码机正在升级中 ... ...","HSM IS BEING UPDATING ... ...");

		/* Adjust the order - Execute the update program - GMN03192005Ro */
		hsmUpdate();
		/* Quit the key manager */
		exit(0);
	}
	else
	{
		HsmSetUpdateAuth(FALSE);
		WriteLine(fd,"程序更新标志已复位.","PROGRAM UPDATE NOT AUTHORIZED.");
	}
	WriteNewLine(fd);
	return 0;
}
