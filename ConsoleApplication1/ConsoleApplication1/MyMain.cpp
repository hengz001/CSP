#include <Windows.h>
#include <stdio.h>
#include "MyMain.h"
#include "csp.h"

#pragma comment(lib,"GMNCSP.lib")

int main(){
	HCRYPTPROV hProv = 0;
	BOOL bf = FALSE;
	int count = 0;

	puts("CSP TEST.");
	//1 CPAcquireContext
	bf = CPAcquireContext(
		//返回的CSP密钥容器的句柄
		&hProv,
		//指定密钥容器名称
		NULL,
		//是否创建/删除容器
		NULL,
		//回调函数列表
		NULL
		);
	 if (bf){
		 printf("SUCCESS COUNT: %d\n",(++count));
	 }
	 else {
		 printf("ERROR %d\n",__LINE__);
	 }
	 DWORD dwLen = 1024;
	 BYTE bValue [1024];
	 DWORD dwFlag = 0;
	//2 CPGetProvParam
	 bf = CPGetProvParam(
		//指定CSP密钥容器
		hProv,
		//查询键
		 (DWORD)"zhuheng001",
		//键值缓存
		 bValue,
		//键值长度
		&dwLen,
		//指定返回键值的一些参数
		dwFlag
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }
	   printf("-------------> len: %u flag: %u buff;%s\n ",dwLen,dwFlag,(char*)bValue);

	//4 CPSetProvParam
	   bf = CPSetProvParam(
		//指定CSP密钥容器句柄
		hProv,
		//设置参数的键
		(DWORD)"zhuheng001",
		//设置参数的键值
		(BYTE*)"zhuheng",
		//指定一些键值相关的参数
		REG_SZ
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//5 CPDeriveKey
	   bf = CPDeriveKey(
		//指定CSP密钥容器句柄
		   hProv,
		//指定产生密钥的算法标识
		NULL,
		//基础数据的HASH值句柄
		NULL,
		//指定session key的一些参数
		NULL,
		//返回密钥对象句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//6 CPDestroyKey
	   bf = CPDestroyKey(
		//指定CSP密钥容器句柄
		   hProv,
		//指定销毁密钥对象句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//7 CPExportKey
	   bf = CPExportKey(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//8 CPGenKey
	   bf = CPGenKey(
		//指定CSP密钥容器句柄
		   hProv,
		//指定产生密钥算法标识
		NULL,
		//指定参数密钥的一些参数
		NULL,
		//返回密钥对象句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//9 CPGenRandom
	   bf = CPGenRandom(
		//指定CSP密钥容器句柄
		   hProv,
		//
		NULL,
		//
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//10 CPGetKeyParam
	   bf = CPGetKeyParam(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//11 CPGetUserKey
	   bf = CPGetUserKey(
		//指定CSP密钥容器句柄
		   hProv,
		//指定密钥规格
		NULL,
		//返回用户密钥句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//12 CPImportKey
	   bf = CPImportKey(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//13 CPSetKeyParam
	   bf = CPSetKeyParam(
		//指定CSP密钥容器句柄
		   hProv,
		//指定目标对象句柄
		NULL,
		//设置密钥对象键
		NULL,
		//设置密钥对象值
		NULL,
		//设置密钥对象值长度
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//14 CPDecrypt
	   bf = CPDecrypt(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//15 CPEncrypt
	   bf = CPEncrypt(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//16 CPCreateHash
	   bf = CPCreateHash(
		//指定CSP密钥容器句柄
		   hProv,
		//指定算法标识
		NULL,
		//指定密钥句柄
		NULL,
		//
		NULL,
		//返回HASH对象句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//17 CPDestroyHash
	   bf = CPDestroyHash(
		//指定CSP密钥容器句柄
		   hProv,
		//指定释放HASH对象句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//18 CPDuplicateHash 附加函数
	   bf = CPDuplicateHash(
		//指定CSP密钥容器句柄
		   hProv,
		//指定被复制的HASH对象
		NULL,
		//必须填NULL
		NULL,
		//必须填0
		NULL,
		//复制的HASH对象
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//19 CPGetHashParam
	   bf = CPGetHashParam(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//20 CPHashData
	   bf = CPHashData(
		//指定CSP密钥容器句柄
		   hProv,
		//指定HASH对象句柄
		NULL,
		//需要计算HASH的数据
		NULL,
		//需要HASH的数据长度
		NULL,
		//
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//21 CPSetHashParam
	   bf = CPSetHashParam(
		//指定CSP密钥容器句柄
		   hProv,
		//指定HASH对象句柄
		NULL,
		//设置参数的键
		NULL,
		//设置参数的值
		NULL,
		//
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//22 CPSignHash
	   bf = CPSignHash(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//23 CPVerifySignature
	   bf = CPVerifySignature(
		//指定CSP密钥容器句柄
		   hProv,
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
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }

	//24 CPDuplicateKey 附加函数
	   bf = CPDuplicateKey(
		//指定CSP密钥容器句柄
		hProv,
		//被复制密钥对象句柄
		NULL,
		//必须填NULL
		NULL,
		//必须填0
		NULL,
		//复制的密钥对象句柄
		NULL
		);
	   if (bf) {
		    printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }
	  
	   //25 CPHashSessionKey
	   bf = CPHashSessionKey(
		//指定CSP密钥容器句柄
		hProv,
		//指定HASH对象句柄
		NULL,
		//指定SESSION KEY对象句柄
		NULL,
		//
		NULL
		);
	   if (bf) {
		   printf("SUCCESS COUNT: %d\n",(++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }


	   //3 CPReleaseContext
	   bf = CPReleaseContext(
		   //释放CSP密钥容器句柄
		   hProv,
		   //flag
		   NULL
	   );
	   if (bf) {
		   printf("SUCCESS COUNT: %d\n", (++count));
	   }
	   else {
		   printf("ERROR %d\n",__LINE__);
	   }


	getchar();
}