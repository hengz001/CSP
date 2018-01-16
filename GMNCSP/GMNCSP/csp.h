//Version1.0 zhuheng20171721100300
/*
//1 CPAcquireContext	SUCCESS
//2 CPGetProvParam		SUCCESS
//3 CPReleaseContext	SUCCESS
//4 CPSetProvParam		SUCCESS
//5 CPDeriveKey		
//6 CPDestroyKey		SUCCESS
//7 CPExportKey		
//8 CPGenKey			SUCCESS
//9 CPGenRandom			SUCCESS
//10 CPGetKeyParam
//11 CPGetUserKey
//12 CPImportKey
//13 CPSetKeyParam
//14 CPDecrypt
//15 CPEncrypt
//16 CPCreateHash
//17 CPDestroyHash
//18 CPDuplicateHash					附加函数
//19 CPGetHashParam
//20 CPHashData
//21 CPSetHashParam
//22 CPSignHash
//23 CPVerifySignature
//24 CPDuplicateKey						附加函数
//25 CPHashSessionKey
*/

#ifndef CSP_SPI
#define CSP_SPI

//DEBUG打印显示信息
#define DEBUG

#define EXPORT
#ifdef EXPORT
#define CSPINTERFACE extern "C" _declspec(dllexport)
//#define CSPINTERFACE 
#else
#define CSPINTERFACE extern "C" _declspec(dllimport)
#endif

typedef struct _VTableProvStruc {
	DWORD   Version;
	FARPROC FuncVerifyImage;
	FARPROC FuncReturnhWnd;
	DWORD   dwProvType;
	BYTE    *pbContextInfo;
	DWORD   cbContextInfo;
	LPSTR   pszProvName;
} VTableProvStruc, *PVTableProvStruc;

//1 CPAcquireContext
CSPINTERFACE BOOL WINAPI CPAcquireContext(
	//返回的CSP密钥容器的句柄
	__out HCRYPTPROV *phProv,
	//指定密钥容器名称
	__in CHAR *pszContainer,
	//是否创建/删除容器
	__in DWORD dwFlags,
	//回调函数列表
	__in PVTableProvStruc pVTable
	);

//2 CPGetProvParam
CSPINTERFACE BOOL WINAPI   CPGetProvParam(
	//指定CSP密钥容器
	__in HCRYPTPROV hProv,
	//查询键
	__in DWORD dwParam,
	//键值缓存
	__out BYTE *pbData,
	//键值长度
	__inout DWORD *pdwDataLen,
	//指定返回键值的一些参数
	__in DWORD dwFlags
	);

//3 CPReleaseContext
CSPINTERFACE BOOL WINAPI   CPReleaseContext(
	//释放CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//flag
	__in DWORD dwFlags
	);

//4 CPSetProvParam
CSPINTERFACE BOOL WINAPI   CPSetProvParam(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//设置参数的键
	__in DWORD dwParam,
	//设置参数的键值
	__in BYTE *pbData,
	//指定一些键值相关的参数
	__in DWORD dwFlags
	);

//5 CPDeriveKey
CSPINTERFACE BOOL WINAPI   CPDeriveKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定产生密钥的算法标识
	__in ALG_ID Algid,
	//基础数据的HASH值句柄
	__in HCRYPTHASH hBaseData,
	//指定session key的一些参数
	__in DWORD dwFlags,
	//返回密钥对象句柄
	__out HCRYPTKEY *phKey
	);

//6 CPDestroyKey
CSPINTERFACE BOOL WINAPI   CPDestroyKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定销毁密钥对象句柄
	__in HCRYPTKEY hKey
	);

//7 CPExportKey
CSPINTERFACE BOOL WINAPI   CPExportKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定需要导出的密钥对象句柄
	__in HCRYPTKEY hKey,
	//加密导出的密钥
	__in HCRYPTKEY hPubKey,
	//指定key BLOB类型
	__in DWORD dwBlobType,
	//
	__in DWORD dwFlags,
	//导出密钥缓存数据
	__out BYTE *pbData,
	//密钥缓存长度
	__inout DWORD *pdwDataLen
	);

//8 CPGenKey
CSPINTERFACE BOOL WINAPI   CPGenKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定产生密钥算法标识
	__in ALG_ID Algid,
	//指定参数密钥的一些参数
	__in DWORD dwFlags,
	//返回密钥对象句柄
	__out HCRYPTKEY *phKey
	);

//9 CPGenRandom
CSPINTERFACE BOOL WINAPI   CPGenRandom(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//
	__in DWORD dwLen,
	//
	__inout BYTE *pbBuffer
	);

//10 CPGetKeyParam
CSPINTERFACE BOOL WINAPI   CPGetKeyParam(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定密钥对象句柄
	__in HCRYPTKEY hKey,
	//参数键
	__in DWORD dwParam,
	//键值缓存
	__out LPBYTE pbData,
	//键值长度
	__inout LPDWORD pcbDataLen,
	//
	__in DWORD dwFlags
	);

//11 CPGetUserKey
CSPINTERFACE BOOL WINAPI   CPGetUserKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定密钥规格
	__in DWORD dwKeySpec,
	//返回用户密钥句柄
	__out HCRYPTKEY *phUserKey
	);

//12 CPImportKey
CSPINTERFACE BOOL WINAPI   CPImportKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//密钥数据（key BLOB）
	__in const BYTE *pbData,
	//key BLOB字节数
	__in DWORD dwDataLen,
	//
	__in HCRYPTKEY hPubKey,
	//指定一些导入密钥的参数
	__in DWORD dwFlags,
	//返回导入密钥的句柄
	__out HCRYPTKEY *phKey
	);

//13 CPSetKeyParam
CSPINTERFACE BOOL WINAPI   CPSetKeyParam(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定目标对象句柄
	__in HCRYPTKEY hKey,
	//设置密钥对象键
	__in DWORD dwParam,
	//设置密钥对象值
	__in BYTE *pbData,
	//设置密钥对象值长度
	__in DWORD dwFlags
	);

//14 CPDecrypt
CSPINTERFACE BOOL WINAPI   CPDecrypt(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//解密密钥句柄
	__in HCRYPTKEY hKey,
	//如果解密后需要计算HASH 指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//是否最后一块
	__in BOOL Final,
	//
	__in DWORD dwFlags,
	//调用前后 分别是 密文数据 明文数据 
	__inout BYTE *pbData,
	//数据长度
	__inout DWORD *pdwDataLen
	);

//15 CPEncrypt
CSPINTERFACE BOOL WINAPI   CPEncrypt(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//加密密钥句柄
	__in HCRYPTKEY hKey,
	//如果加密前需要计算HASH 指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//是否是加密的最后一块
	__in BOOL Final,
	//
	__in DWORD dwFlags,
	//调用前后 分别是 明文数据 密文数据
	__inout BYTE *pbData,
	//数据长度
	__inout DWORD *pdwDataLen,
	//pbData的总长度
	__in DWORD dwBufLen
	);

//16 CPCreateHash
CSPINTERFACE BOOL WINAPI   CPCreateHash(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定算法标识
	__in ALG_ID Algid,
	//指定密钥句柄
	__in HCRYPTKEY hKey,
	//
	__in DWORD dwFlags,
	//返回HASH对象句柄
	__out HCRYPTHASH *phHasg
	);

//17 CPDestroyHash
CSPINTERFACE BOOL WINAPI   CPDestroyHash(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定释放HASH对象句柄
	__in HCRYPTHASH hHash
	);

//18 CPDuplicateHash 附加函数
CSPINTERFACE BOOL WINAPI   CPDuplicateHash(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定被复制的HASH对象
	__in HCRYPTHASH hHash,
	//必须填NULL
	__reserved DWORD *pdwReserved,
	//必须填0
	__in DWORD dwFlags,
	//复制的HASH对象
	__out HCRYPTHASH *phHash
	);

//19 CPGetHashParam
CSPINTERFACE BOOL WINAPI   CPGetHashParam(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//参数键
	__in DWORD dwParam,
	//返回键值对应的数据缓存
	__out BYTE *pbData,
	//返回数据长度
	__inout DWORD *pdwDataLen,
	//
	__in DWORD dwFlags
	);

//20 CPHashData
CSPINTERFACE BOOL WINAPI   CPHashData(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//需要计算HASH的数据
	__in const BYTE *pbData,
	//需要HASH的数据长度
	__in DWORD dwDataLen,
	//
	__in DWORD dwFlags
	);

//21 CPSetHashParam
CSPINTERFACE BOOL WINAPI   CPSetHashParam(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//设置参数的键
	__in DWORD dwParam,
	//设置参数的值
	__in BYTE *pbData,
	//
	__in DWORD dwFlags
	);

//22 CPSignHash
CSPINTERFACE BOOL WINAPI   CPSignHash(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//所使用的密钥规格
	__in DWORD dwKeySpec,
	//询问用户是否知晓什么信息被签名时的提示描述
	__in LPCWSTR sDescription,
	//
	__in DWORD dwFlags,
	// 签名结果
	__out BYTE *pbSignature,
	//签名结果长度
	__inout DWORD *pdwSigLen
	);

//23 CPVerifySignature
CSPINTERFACE BOOL WINAPI   CPVerifySignature(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//签名结果
	__in const BYTE *pbSignature,
	//签名结果长度
	__in DWORD dwSigLen,
	//验签公钥
	__in HCRYPTKEY hPubKey,
	//提示描述
	__in LPCWSTR sDescription,
	//
	__in DWORD dwFlags
	);

//24 CPDuplicateKey 附加函数
CSPINTERFACE BOOL WINAPI   CPDuplicateKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hUID,
	//被复制密钥对象句柄
	__in HCRYPTKEY hKey,
	//必须填NULL
	__in DWORD *pdwReserved,
	//必须填0
	__in DWORD dwFlags,
	//复制的密钥对象句柄
	__out HCRYPTKEY *phKey
	);

//25 CPHashSessionKey
CSPINTERFACE BOOL WINAPI   CPHashSessionKey(
	//指定CSP密钥容器句柄
	__in HCRYPTPROV hProv,
	//指定HASH对象句柄
	__in HCRYPTHASH hHash,
	//指定SESSION KEY对象句柄
	__in HCRYPTKEY hKey,
	//
	__in DWORD dwFlags
	);

#endif