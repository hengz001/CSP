#ifndef __BACKUP__
#define __BACKUP__

/*
*早期源码备份 方便查询 无需编译.
*/


#if 0

int CPAcquireContextImpl();

int CPGetProvParamImpl(HCRYPTPROV hProv, DWORD dwParam, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

int CPSetProvParamImpl(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPDeriveKeyImpl(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, HCRYPTKEY *phKey);

int CPExportKeyImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, BYTE *pbData, DWORD *pdwDataLen);

int CPGenKeyImpl(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);

int CPGenRandomImpl(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);

int CPGetKeyParamImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen);

int CPGetUserKeyImpl(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey);

int CPImportKeyImpl(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey);

int CPSetKeyParamImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPDecryptImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

int CPEncryptImpl(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);

int CPCreateHashImpl(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);

int CPGetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);

int CPHashDataImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);

int CPSetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPSignHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR sDescription, DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen);

int CPVerifySignatureImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR sDescription, DWORD dwFlags);

int CPHashSessionKeyImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags);
#endif

#endif
