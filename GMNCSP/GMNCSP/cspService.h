
int initCSP(void);

int testSjl22(void);

int genrsakeyImpl(HCRYPTPROV hProv,DWORD dwFlags, PHPKEY_Z pKey, int comid, int Algid);

int exportrsadeskeyImpl(HCRYPTKEY hKey, HCRYPTKEY hPubKey, UCHAR * data, int * data_length);

int importrsadeskeyImpl(UCHAR * data, int data_length, UCHAR * private_key, int  private_key_len, UCHAR * wkLmk, int * keylen, UCHAR * cv);

int encryptDecryptImpl();

int genhashImpl();

int rsaprisignImpl();

int rsapubverifyImpl();

int generateKeyImpl(int comid, PHKEY_Z  hKey,int algo);

int initJudgment(HCRYPTPROV hProv);

int getKeyParam(DWORD dwParam, HKEY_Z * tmpKey, LPBYTE pbData, LPDWORD pcbDataLen);

int getKeyParamImpl(CHAR * data, LPBYTE pbData, LPDWORD pcbDataLen);

int getHashParam(DWORD dwParam, PHHASH_Z phzHash, LPBYTE pbData, LPDWORD pdwDataLen);

int genSm2Key(PHKEY_Z hKey, int comid, int Algid);

int decryptDES(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int encryptDES(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptRSA(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int encryptRSA(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptSM2(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int encryptSM2(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptAlgo(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int encryptAlgo(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

