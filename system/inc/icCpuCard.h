
int IcOpenDevice(void);

int IcCloseDevice(int icdev);

int IcResetDevice(int icdev, char *devid);

int IcReadIdentity(int icdev, icInfo_t *id, char *reply);

int IcReadData(int icdev, int offset, char *pin, unsigned char *data, int len,char *reply);
