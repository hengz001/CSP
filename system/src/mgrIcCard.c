#include "mgrSvr.h"

int gmnReadParmFromCard(racal_cfg_t *hsmcfg) {
	return _read_nvram((unsigned char *) hsmcfg, sizeof(racal_cfg_t));
}

int gmnWriteParmToCard(racal_cfg_t *hsmcfg) {
	return _write_nvram((unsigned char *) hsmcfg, sizeof(racal_cfg_t));
}

int ReadConfigAndSaveTOCard(void) {

	int icdev;
	char resp[256];
	char pin[16];
	icInfo_t icInfo;
	racal_cfg_t hsm_cfg;
	racal_cfg_t hsm_cfg_r;
	int rc;

	if ((icdev = IcOpenDevice()) < 0) {
		return -1;
	}

	if ((IcResetDevice(icdev, resp)) < 0) {
		IcCloseDevice(icdev);
		return -1;
	}
	memset(pin, 0, sizeof(pin));
	strcpy(pin, "621224");

	if ((IcReadIdentity(icdev, &icInfo, resp)) < 0) {
		IcCloseDevice(icdev);
		return -1;
	}

	switch (icInfo.usage_id) {
	case IC_CONF_PARM:	//参数配置卡
		break;

	default:
		dv_beep(icdev, LONG_BEEP);
		IcCloseDevice(icdev);
		return (-1);
	}

	//读配置卡数据
	rc = IcReadData(icdev, 0, pin, (UCHAR *) &hsm_cfg, sizeof(racal_cfg_t),
			resp);
	if (rc < 0) {
		dv_beep(icdev, LONG_BEEP);
		IcCloseDevice(icdev);
		return -1;
	}

	//加密机内存参数
	rc = gmnReadParmFromCard(&hsm_cfg_r);
	if (rc < 0) {
		dv_beep(icdev, LONG_BEEP);
		IcCloseDevice(icdev);
		return -1;
	}

	//加密机序列号不更改
	memcpy(&hsm_cfg.hsm_sn, &hsm_cfg_r.hsm_sn, 16);

	rc = gmnWriteParmToCard(&hsm_cfg);
	if (rc < 0) {
		dv_beep(icdev, LONG_BEEP);
		IcCloseDevice(icdev);
		return -1;
	}

	rc = gmnReadParmFromCard(&hsm_cfg_r);
	if (rc < 0) {
		dv_beep(icdev, LONG_BEEP);
		IcCloseDevice(icdev);
		return -1;
	}

	rc = memcmp(&hsm_cfg_r, &hsm_cfg, sizeof(racal_cfg_t));
	if (rc==0) {
		dv_beep(icdev, SHORT_BEEP);
	} else {
		dv_beep(icdev, LONG_BEEP);
	}

	IcCloseDevice(icdev);

	sync();
	sleep(1);

	return reboot(RB_AUTOBOOT);
}

