
#ifndef __CSP_SERVICE_IMPL__
#define __CSP_SERVICE_IMPL__

/*
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

int CPHashDataImpl( HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);

int CPSetHashParamImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

int CPSignHashImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR sDescription, DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen);

int CPVerifySignatureImpl(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR sDescription, DWORD dwFlags);

int CPHashSessionKeyImpl( HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey,DWORD dwFlags);
*/

//1 CPAcquireContext
int cpAcquireContextImpl(HCRYPTPROV *phProv,CHAR *pszContainer,DWORD dwFlags,PVTableProvStruc pVTable);

//2 cpGetProvParam
int   cpGetProvParamImpl(HCRYPTPROV hProv,DWORD dwParam,BYTE *pbData,DWORD *pdwDataLen,DWORD dwFlags);

//3 cpReleaseContext
int   cpReleaseContextImpl(HCRYPTPROV hProv,DWORD dwFlags);

//4 cpSetProvParam
int   cpSetProvParamImpl(HCRYPTPROV hProv,DWORD dwParam,BYTE *pbData,DWORD dwFlags);

//5 cpDeriveKey
int   cpDeriveKeyImpl(HCRYPTPROV hProv,ALG_ID Algid,HCRYPTHASH hBaseData,DWORD dwFlags,HCRYPTKEY *phKey);

//6 cpDestroyKey
int   cpDestroyKeyImpl(HCRYPTPROV hProv,HCRYPTKEY hKey);

//7 cpExportKey
int   cpExportKeyImpl(HCRYPTPROV hProv,HCRYPTKEY hKey,HCRYPTKEY hPubKey,DWORD dwBlobType,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen);

//8 cpGenKey
int   cpGenKeyImpl(HCRYPTPROV hProv,ALG_ID Algid,DWORD dwFlags,HCRYPTKEY *phKey);

//9 cpGenRandom
int   cpGenRandomImpl(HCRYPTPROV hProv,DWORD dwLen,BYTE *pbBuffer);

//10 cpGetKeyParam
int   cpGetKeyParamImpl(HCRYPTPROV hProv,HCRYPTKEY hKey,DWORD dwParam,LPBYTE pbData,LPDWORD pcbDataLen,DWORD dwFlags);

//11 cpGetUserKey
int   cpGetUserKeyImpl(HCRYPTPROV hProv,DWORD dwKeySpec,HCRYPTKEY *phUserKey);

//12 cpImportKey
int   cpImportKeyImpl(HCRYPTPROV hProv,const BYTE *pbData,DWORD dwDataLen,HCRYPTKEY hPubKey,DWORD dwFlags,HCRYPTKEY *phKey);

//13 cpSetKeyParam
int   cpSetKeyParamImpl(HCRYPTPROV hProv,HCRYPTKEY hKey,DWORD dwParam,BYTE *pbData,DWORD dwFlags);

//14 cpDecrypt
int   cpDecryptImpl(HCRYPTPROV hProv,HCRYPTKEY hKey,HCRYPTHASH hHash,BOOL Final,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen);

//15 cpEncrypt
int   cpEncryptImpl(HCRYPTPROV hProv,HCRYPTKEY hKey,HCRYPTHASH hHash,BOOL Final,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen,DWORD dwBufLen);

//16 cpCreateHash
int   cpCreateHashImpl(HCRYPTPROV hProv,ALG_ID Algid,HCRYPTKEY hKey,DWORD dwFlags,HCRYPTHASH *phHash);

//17 cpDestroyHash
int   cpDestroyHashImpl(HCRYPTPROV hProv,HCRYPTHASH hHash);

//18 cpDuplicateHash 附加函数
int   cpDuplicateHashImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,DWORD *pdwReserved,DWORD dwFlags,HCRYPTHASH *phHash);

//19 cpGetHashParam
int   cpGetHashParamImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,DWORD dwParam,BYTE *pbData,DWORD *pdwDataLen,DWORD dwFlags);

//20 cpHashData
int   cpHashDataImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,const BYTE *pbData,DWORD dwDataLen,DWORD dwFlags);

//21 cpSetHashParam
int   cpSetHashParamImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,DWORD dwParam,BYTE *pbData,DWORD dwFlags);

//22 cpSignHash
int   cpSignHashImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,DWORD dwKeySpec,LPCWSTR sDescription,DWORD dwFlags,BYTE *pbSignature,DWORD *pdwSigLen);

//23 cpVerifySignature
int   cpVerifySignatureImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,const BYTE *pbSignature,DWORD dwSigLen,HCRYPTKEY hPubKey,LPCWSTR sDescription,DWORD dwFlags);

//24 cpDuplicateKey 附加函数
int   cpDuplicateKeyImpl(HCRYPTPROV hUID,HCRYPTKEY hKey,DWORD *pdwReserved,DWORD dwFlags,HCRYPTKEY *phKey);

//25 cpHashSessionKey
int   cpHashSessionKeyImpl(HCRYPTPROV hProv,HCRYPTHASH hHash,HCRYPTKEY hKey,DWORD dwFlags);

#endif