
int initCSP(void);

int testSjl22(void);

int genrsakeyImpl(DWORD dwFlags, HPKEY_Z *pKey, int comid);

int exportrsadeskeyImpl(HCRYPTKEY hKey, HCRYPTKEY hPubKey, UCHAR * data, int * data_length);

int importrsadeskeyImpl(UCHAR * data, int data_length, UCHAR * private_key, int  private_key_len, UCHAR * wkLmk, int * keylen, UCHAR * cv);