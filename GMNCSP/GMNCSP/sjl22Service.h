

#ifndef __SJL22_SERVICE__
#define __SJL22_SERVICE__

int initializeCSPService(HCRYPTPROV *phProv);

int initJudgmentService(HCRYPTPROV hProv);

int exportrsadeskeyService(HCRYPTKEY hKey, HCRYPTKEY hPubKey, UCHAR * data, int * data_length);

int getKeyParamService(DWORD dwParam, HKEY_Z * tmpKey, LPBYTE pbData, LPDWORD pcbDataLen);

int getHashParamService(DWORD dwParam, PHHASH_Z phzHash, LPBYTE pbData, LPDWORD pdwDataLen);

int hashDataService(int comid, PHHASH_Z phzHash, const BYTE *pbData, DWORD dwDataLen);

int derivatekeyService(int comid, PHKEY_Z phKey, ALG_ID Algid, HCRYPTHASH hBaseData);

int encryptService(int comid, PHKEY_Z phKey, BYTE *pbData, DWORD *pdwDataLen);

int decryptService(int comid, PHKEY_Z phKsignatureRSAServiceImpley, BYTE *pbData, DWORD *pdwDataLen);

int signatureService(int comid, PHKEY_Z phKey, BYTE *pbSignature, DWORD *dwSigLen, PHHASH_Z phzHash);

int verifyService(int comid, PHKEY_Z phKey, const BYTE *pbSignature, DWORD dwSigLen, PHHASH_Z phzHash);

int getParamService(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);

int setParamService(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int genKeyService(int comid, HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);

int genRandomService(int comid, DWORD dwLen, BYTE *pbBuffer);

int getUserKeyService(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey);

int importKeyService(const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey);

int setKeyParamService(PHKEY_Z phKey, DWORD dwParam, BYTE *pbData);

int createHashService(ALG_ID Algid, HCRYPTKEY hKey, HCRYPTHASH *phHash);

int duplicateHashService(HCRYPTHASH hHash, HCRYPTHASH *phHash);

int setHashParamService(PHHASH_Z phzHash, DWORD dwParam, DWORD pdwDataLen, BYTE *pbData);

int duplicateKeyService(HCRYPTKEY hKey, HCRYPTKEY *phKey);

int hashKeyService(int comid, PHHASH_Z phzHash);

#endif
