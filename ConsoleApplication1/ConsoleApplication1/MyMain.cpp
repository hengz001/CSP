#include <Windows.h>
#include <stdio.h>
#include "MyMain.h"
#include "csp.h"

#pragma comment(lib,"GMNCSP.lib")

int main(){
	HCRYPTPROV phProv;
	BOOL bv = FALSE;
		 

	puts("CSP TEST.");
	//1 CPAcquireContext
	bv =  CPAcquireContext(
		//返回的CSP密钥容器的句柄
		&phProv,
		//指定密钥容器名称
		NULL,
		//是否创建/删除容器
		NULL,
		//回调函数列表
		NULL
		);
	 if (bv){
		 puts("CPAcquireContext SUCCESS.");
	 }

	//2 CPGetProvParam
	   CPGetProvParam(
		//指定CSP密钥容器
		NULL,
		//查询键
		NULL,
		//键值缓存
		NULL,
		//键值长度
		NULL,
		//指定返回键值的一些参数
		NULL
		);

	//3 CPReleaseContext
	   CPReleaseContext(
		//释放CSP密钥容器句柄
		NULL,
		//flag
		NULL
		);

	//4 CPSetProvParam
	   CPSetProvParam(
		//指定CSP密钥容器句柄
		NULL,
		//设置参数的键
		NULL,
		//设置参数的键值
		NULL,
		//指定一些键值相关的参数
		NULL
		);

	//5 CPDeriveKey
	   CPDeriveKey(
		//指定CSP密钥容器句柄
		NULL,
		//指定产生密钥的算法标识
		NULL,
		//基础数据的HASH值句柄
		NULL,
		//指定session key的一些参数
		NULL,
		//返回密钥对象句柄
		NULL
		);

	//6 CPDestroyKey
	   CPDestroyKey(
		//指定CSP密钥容器句柄
		NULL,
		//指定销毁密钥对象句柄
		NULL
		);

	//7 CPExportKey
	   CPExportKey(
		//指定CSP密钥容器句柄
		NULL,
		//指定需要导出的密钥对象句柄
		NULL,
		//加密导出的密钥
		NULL,
		//指定key BLOB类型
		NULL,
		//
		NULL,
		//导出密钥缓存数据
		NULL,
		//密钥缓存长度
		NULL
		);

	//8 CPGenKey
	   CPGenKey(
		//指定CSP密钥容器句柄
		NULL,
		//指定产生密钥算法标识
		NULL,
		//指定参数密钥的一些参数
		NULL,
		//返回密钥对象句柄
		NULL
		);

	//9 CPGenRandom
	   CPGenRandom(
		//指定CSP密钥容器句柄
		NULL,
		//
		NULL,
		//
		NULL
		);

	//10 CPGetKeyParam
	   CPGetKeyParam(
		//指定CSP密钥容器句柄
		NULL,
		//指定密钥对象句柄
		NULL,
		//参数键
		NULL,
		//键值缓存
		NULL,
		//键值长度
		NULL,
		//
		NULL
		);

	//11 CPGetUserKey
	   CPGetUserKey(
		//指定CSP密钥容器句柄
		NULL,
		//指定密钥规格
		NULL,
		//返回用户密钥句柄
		NULL
		);

	//12 CPImportKey
	   CPImportKey(
		//指定CSP密钥容器句柄
		NULL,
		//密钥数据（key BLOB）
		NULL,
		//key BLOB字节数
		NULL,
		//
		NULL,
		//指定一些导入密钥的参数
		NULL,
		//返回导入密钥的句柄
		NULL
		);

	//13 CPSetKeyParam
	   CPSetKeyParam(
		//指定CSP密钥容器句柄
		NULL,
		//指定目标对象句柄
		NULL,
		//设置密钥对象键
		NULL,
		//设置密钥对象值
		NULL,
		//设置密钥对象值长度
		NULL
		);

	//14 CPDecrypt
	   CPDecrypt(
		//指定CSP密钥容器句柄
		NULL,
		//解密密钥句柄
		NULL,	
		//如果解密后需要计算HASH 指定HASH对象句柄
		NULL,
		//是否最后一块
		NULL,
		//
		NULL,
		//调用前后 分别是 密文数据 明文数据 
		NULL,
		//数据长度
		NULL
		);

	//15 CPEncrypt
	   CPEncrypt(
		//指定CSP密钥容器句柄
		NULL,
		//加密密钥句柄
		NULL,
		//如果加密前需要计算HASH 指定HASH对象句柄
		NULL,
		//是否是加密的最后一块
		NULL,
		//
		NULL,
		//调用前后 分别是 明文数据 密文数据
		NULL,
		//数据长度
		NULL,
		//pbData的总长度
		NULL
		);

	//16 CPCreateHash
	   CPCreateHash(
		//指定CSP密钥容器句柄
		NULL,
		//指定算法标识
		NULL,
		//指定密钥句柄
		NULL,
		//
		NULL,
		//返回HASH对象句柄
		NULL
		);

	//17 CPDestroyHash
	   CPDestroyHash(
		//指定CSP密钥容器句柄
		NULL,
		//指定释放HASH对象句柄
		NULL
		);

	//18 CPDuplicateHash 附加函数
	   CPDuplicateHash(
		//指定CSP密钥容器句柄
		NULL,
		//指定被复制的HASH对象
		NULL,
		//必须填NULL
		NULL,
		//必须填0
		NULL,
		//复制的HASH对象
		NULL
		);

	//19 CPGetHashParam
	   CPGetHashParam(
		//指定CSP密钥容器句柄
		NULL,
		//指定HASH对象句柄
		NULL,
		//参数键
		NULL,
		//返回键值对应的数据缓存
		NULL,
		//返回数据长度
		NULL,
		//
		NULL
		);

	//20 CPHashData
	   CPHashData(
		//指定CSP密钥容器句柄
		NULL,
		//指定HASH对象句柄
		NULL,
		//需要计算HASH的数据
		NULL,
		//需要HASH的数据长度
		NULL,
		//
		NULL
		);

	//21 CPSetHashParam
	   CPSetHashParam(
		//指定CSP密钥容器句柄
		NULL,
		//指定HASH对象句柄
		NULL,
		//设置参数的键
		NULL,
		//设置参数的值
		NULL,
		//
		NULL
		);

	//22 CPSignHash
	   CPSignHash(
		//指定CSP密钥容器句柄
		NULL,
		//指定HASH对象句柄
		NULL,
		//所使用的密钥规格
		NULL,
		//询问用户是否知晓什么信息被签名时的提示描述
		NULL,
		//
		NULL,
		// 签名结果
		NULL,
		//签名结果长度
		NULL
		);

	//23 CPVerifySignature
	   CPVerifySignature(
		//指定CSP密钥容器句柄
		NULL,
		//指定HASH对象句柄
		NULL,
		//签名结果
		NULL,
		//签名结果长度
		NULL,
		//验签公钥
		NULL,
		//提示描述
		NULL,
		//
		NULL
		);

	//24 CPDuplicateKey 附加函数
	   CPDuplicateKey(
		//指定CSP密钥容器句柄
		NULL,
		//被复制密钥对象句柄
		NULL,
		//必须填NULL
		NULL,
		//必须填0
		NULL,
		//复制的密钥对象句柄
		NULL
		);

	//25 CPHashSessionKey
	   CPHashSessionKey(
		//指定CSP密钥容器句柄
		NULL,
		//指定HASH对象句柄
		NULL,
		//指定SESSION KEY对象句柄
		NULL,
		//
		NULL
		);



	getchar();
}