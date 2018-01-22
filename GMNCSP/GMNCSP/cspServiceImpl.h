
#ifndef __CSP_SERVICE_IMPL__
#define __CSP_SERVICE_IMPL__

int CPAcquireContextImpl();

int CPGetProvParamImpl(DWORD dwParam, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

int CPSetProvParamImpl(DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPDeriveKeyImpl(ALG_ID Algid, HCRYPTHASH hBaseData, HCRYPTKEY *phKey);

int CPExportKeyImpl(HCRYPTKEY hKey, HCRYPTKEY hPubKey, BYTE *pbData, DWORD *pdwDataLen);

int CPGenKeyImpl(ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);

int CPGenRandomImpl(DWORD dwLen, BYTE *pbBuffer);

int CPGetKeyParamImpl(HCRYPTKEY hKey, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen);

int CPGetUserKeyImpl(DWORD dwKeySpec, HCRYPTKEY *phUserKey);

int CPImportKeyImpl(const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey);

int CPSetKeyParamImpl(HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPDecryptImpl(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

int CPEncryptImpl(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);

int CPCreateHashImpl(ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);

int CPGetHashParamImpl(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);

int CPHashDataImpl( HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);

////
int CPSetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPSignHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR sDescription, DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen);

#endif