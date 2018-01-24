
#ifndef __SJL22_SERVICE_IMPLEMENTS__
#define __SJL22_SERVICE_IMPLEMENTS__

int initCspServiceImpl(void);

int testSjl22ServiceImpl(void);

int getKeyParamServiceImpl(CHAR * data, LPBYTE pbData, LPDWORD pcbDataLen);

int encryptRSAServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptRSAServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int encryptSM2ServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptSM2ServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int encryptDataServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptDataServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int signatureRSAServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbSignature, DWORD *dwSigLen, PHHASH_Z phzHash);

int signatureSM2ServiceImpl(int comid, PHKEY_Z phKey, BYTE *pbSignature, DWORD *dwSigLen, PHHASH_Z phzHash);

int verifyRSAServiceImpl(int comid, PHKEY_Z phKey, const BYTE *pbSignature, DWORD dwSigLen, PHHASH_Z phzHash);

int verifySM2ServiceImpl(int comid, PHKEY_Z phKey, const BYTE *pbSignature, DWORD dwSigLen, PHHASH_Z phzHash);

int genSm2KeyServiceImpl(PHKEY_Z hKey, int comid, int Algid);

int genrsakeyServiceImpl(HCRYPTPROV hProv, DWORD dwFlags, PHPKEY_Z pKey, int comid, int Algid);

int generateKeyServiceImpl(int comid, PHKEY_Z  hKey, int algo);

int importrsadeskeyServiceImpl(UCHAR * data, int data_length, UCHAR * private_key, int  private_key_len, UCHAR * wkLmk, int * keylen, UCHAR * cv);


#endif
