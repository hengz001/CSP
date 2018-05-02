#include "tcpSvr.h"
//   ON/OFF 0/1
//int debug = 0;
int debug = 1;

int  goldsockfd;
int  gsockfd[MAX_TCP_CONNECT_NO];

pthread_t thread_com_id[MAX_TCP_CONNECT_NO];

pthread_attr_t attr;

pthread_mutex_t   shmMutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t   tcpMutex = PTHREAD_MUTEX_INITIALIZER;

sigset_t threadset, ctrlset;

typedef struct {
	int     sockfd;
	int     thread_id;
} TCPCOMM;

int isClientAccessAllowed(ULONG ip);
int GetFreeThreadCommID(void);
void CountCurrentTcpConnectNumDown(void);

void *HsmCommThread(void *arg)
{
	int sockfd;
	int thread_id;
	pthread_mutex_lock(&tcpMutex);

	sockfd = ((TCPCOMM *)arg)->sockfd;
	thread_id = ((TCPCOMM *)arg)->thread_id;

	free(arg);
	pthread_mutex_unlock(&tcpMutex);

	//县城结束自动释放资源
	pthread_detach(pthread_self());

	//信号集
	pthread_sigmask(SIG_UNBLOCK, &threadset, NULL);
	pthread_sigmask(SIG_BLOCK, &ctrlset, NULL);

	hsmCmdHandle(sockfd);

	comTcpSocketClose(sockfd);

	pthread_mutex_lock(&tcpMutex);

	gsockfd[thread_id] = -1;
	thread_com_id[thread_id] = 0;
	CountCurrentTcpConnectNumDown();

	pthread_mutex_unlock(&tcpMutex);
	pthread_exit(NULL);
	return NULL;
}

int main(int argc, char *argv[]){
	int i;
	int	CurrentConnectNum;
	int	nsockfd;
	ULONG netaddr;
	TCPCOMM *TcpComm;
	int status;

	//守护进程
	hsmDaemon( debug );

	// 内存检测
	if(attachShm()<0)
	{
		_exit(-1);
	}

	//设置网络
	ChangeNet(HsmGetDeviceAddress(),
			HsmGetNetMask(),
			HsmGetNetBroadcast(),
			HsmGetGatewayAddress(),
			"eth0");

	//获得pid
	phsmShm->pid_tcp = getpid();

	//设置联机
	HsmSetOnLine();

	pthread_mutex_init(&shmMutex,NULL);
	pthread_mutex_init(&tcpMutex,NULL);
	//中断各种信号

	//
	if((goldsockfd=comTcpSvrSocketOpen(HsmGetDevicePort())) < 0){
		_exit(-1);
	}

	for(i=0; i<HsmGetMaxTcpConnectNo(); i++){
		gsockfd[i] = -1;
		thread_com_id[i] = 0;
	}
	CurrentConnectNum=0;
	HsmSetCurrentThreadNum ( CurrentConnectNum );

	//调用openssl
	for(;;){
		int tid;

		nsockfd = comTcpAccept(goldsockfd,&netaddr);
		if(nsockfd<0){
			continue;
		}

		if(!isHsmOnLine()){
			comTcpSocketClose(nsockfd);
			continue;
		}

		if(hsmTcpAllowAccessControl()){
			if(!isClientAccessAllowed(netaddr)){
				comTcpSocketClose(nsockfd);
				continue;
			}
		}
		//锁
		pthread_mutex_lock(&shmMutex);
		//当前连接数
		CurrentConnectNum = HsmGetCurrentThreadNum();
		if ( CurrentConnectNum >= HsmGetMaxTcpConnectNo() )
		{
			comTcpSocketClose(nsockfd);
			pthread_mutex_unlock(&shmMutex);
			continue;
		}else{
			CurrentConnectNum++;
			HsmSetCurrentThreadNum(CurrentConnectNum);
		}
		//解锁
		pthread_mutex_unlock(&shmMutex);
		//
		if((tid = GetFreeThreadCommID())<0){
			comTcpSocketClose(nsockfd);
			CountCurrentTcpConnectNumDown();
			continue;
		}
		//
		TcpComm = (TCPCOMM *)malloc(sizeof(TCPCOMM));
		if(TcpComm == NULL){
			gsockfd[tid] = -1;
			thread_com_id[tid] = 0;
			comTcpSocketClose(nsockfd);
			CountCurrentTcpConnectNumDown();
			continue;
		}
		//
		pthread_mutex_lock(&shmMutex);

		TcpComm->sockfd = nsockfd;
		TcpComm->thread_id = tid;
		gsockfd[tid] = nsockfd;

		status = pthread_create(&thread_com_id[tid], &attr,HsmCommThread,TcpComm);

		pthread_mutex_unlock(&shmMutex);
		if(status != 0){
			comTcpSocketClose(nsockfd);
			CountCurrentTcpConnectNumDown();
			free(TcpComm);
			gsockfd[tid] = -1;
			thread_com_id[tid] = 0;
		}
	}
	comTcpSocketClose(goldsockfd);
	_exit(0);
	return 0;
}

int isClientAccessAllowed(ULONG ip)
{
	int i;
	client_t *ipTable;

	for(i=0; i<MAX_CLIENTS; i++){
		ipTable = &phsmShm->hsmcfg.rCh.client[i];
		if(ip == ipTable->ip){
			if(!isBufferAllTheSameChar((char*)ipTable->hw,0,6)){
				UCHAR hwa[6];

				if(get_hw_address(ipTable->ip,hwa)){
					if(!memcmp(ipTable->hw,hwa,6)){
						return TRUE;
					}
				}
				return FALSE;
			}
			return TRUE;
		}
	}
	return FALSE;
}

int GetFreeThreadCommID(void)
{
	int i;
	pthread_mutex_lock(&shmMutex);

	for(i=0; i<HsmGetMaxTcpConnectNo(); i++)
	{
		if(thread_com_id[i] == 0L)
		{
			thread_com_id[i] = i;
			pthread_mutex_unlock(&shmMutex);
			return i;
		}
	}
	pthread_mutex_unlock(&shmMutex);
	return -1;
}

void CountCurrentTcpConnectNumDown(void)
{
	int CurrentConnectNum;

	pthread_mutex_lock(&shmMutex);
	CurrentConnectNum = HsmGetCurrentThreadNum();
	HsmSetCurrentThreadNum(CurrentConnectNum-1>0?CurrentConnectNum-1:0);
	pthread_mutex_unlock(&shmMutex);
}





