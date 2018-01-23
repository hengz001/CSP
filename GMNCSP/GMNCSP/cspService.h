
int initCSP(void);

int testSjl22(void);

int genrsakeyImpl(HCRYPTPROV hProv,DWORD dwFlags, PHPKEY_Z pKey, int comid);

int exportrsadeskeyImpl(HCRYPTKEY hKey, HCRYPTKEY hPubKey, UCHAR * data, int * data_length);

int importrsadeskeyImpl(UCHAR * data, int data_length, UCHAR * private_key, int  private_key_len, UCHAR * wkLmk, int * keylen, UCHAR * cv);

int encryptDecryptImpl();

int genhashImpl();

int rsaprisignImpl();

int rsapubverifyImpl();

int generateKeyImpl(int comid, PHKEY_Z  hKey);

int initJudgment(HCRYPTPROV hProv);




