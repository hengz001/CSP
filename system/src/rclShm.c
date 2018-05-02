#include <mgrSvr.h>

int attachShm(void)
{
	//create share memory
	if((hsmShmID = shmget(HSM_SHMKEY,sizeof(struct hsmShmStr),IPC_CREAT|HSM_SHMPER))<0)
	{
		return -1;
	}
	//attach share memory
	if((phsmShm = (struct hsmShmStr *)shmat(hsmShmID,(char*)0,0)) == (struct hsmShmStr *)-1){
		return -1;
	}
	return 0;
}

void HsmSetUpdateAuth(int iflag)
{
	phsmShm->upd_authed = iflag;
}

void HsmResetUpdateFlag(void)
{
	HsmSetUpdateAuth(FALSE);
}

