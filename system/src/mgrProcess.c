#include "mgrSvr.h"

int hsmStartProcess(int prg)
{
	int status;
	pid_t pid;

	pid = vfork();
	if(pid==0){
		char path[256];
		getcwd(path,sizeof(path));
		strcpy(path+strlen(path),"/");
		switch (prg) {
			case PROG_MAIN_TCP:
				strcpy(path+strlen(path), "gmntcp");
				execl(path, "gmntcp", NULL);
				break;
			case PROG_MAIN_MON:
				strcpy(path+strlen(path),"gmnmon");
				execl(path,"gmnmon",NULL);
				break;
			default:
				break;
		}
		exit(0);
	}
	waitpid(pid,&status,0);
	return 0;
}

int StartTcpNhMainProcess(void)
{
	return 0;
}

int StartTcpMainProcess(void)
{
	return hsmStartProcess( PROG_MAIN_TCP );
}


int StartMonMainProcess(void)
{
	return hsmStartProcess(PROG_MAIN_MON);
}
