#include "mgrSvr.h"

// ON/OFF 0/1
static int debug = 0;
//static int debug = 1;


int main(int argc, char *argv[]){
	int dev_kstoreLPSRAM, dev_kstoreNVRAM;
	UINT status = 0;
	pid_t pid;

	hsmDaemon(debug);
	if(attachShm()<0){
		exit(-1);
	}

	pid = fork();
	if(pid<0){
		_exit(0);
	}
	if(pid==0){
		dev_kstoreLPSRAM = open("/dev/kstore0",O_RDWR);
		if(dev_kstoreLPSRAM == -1){
			exit(0);
		}
		while(1){
			ioctl(dev_kstoreLPSRAM,CARD_BLOCKOFFLINE,&status);
			if(status == 1){
				if(phsmShm->hsm_state == HSM_ONLINE){
					perror("ioctl interrupt offline!");
					phsmShm->sense_byte = HSM_STATE_OFFLINE;
					kill(phsmShm->pid_mgr,SIG_HSM_INTERRUPT);
				}
			}
			sleep(1);
		}
		close(dev_kstoreLPSRAM);
		_exit(0);
	}else{
		dev_kstoreNVRAM = open("/dev/kstore1",O_RDWR);
		if(dev_kstoreNVRAM == -1){
			exit(0);
		}
		while(1){
			ioctl(dev_kstoreNVRAM,CARD_BLOCKALERT,&status);
			if(status == HSM_STATE_NORMAL && phsmShm->hsm_armed == HSM_STATE_ARMED)
			{
				phsmShm->sense_byte = HSM_STATE_NORMAL;
				kill(phsmShm->pid_mgr,SIG_HSM_INTERRUPT);
			}
			else if(status == HSM_STATE_ARMED && phsmShm->hsm_armed == HSM_STATE_NORMAL){
				phsmShm->sense_byte = HSM_STATE_ARMED;
				kill(phsmShm->pid_mgr,SIG_HSM_INTERRUPT);
			}
			sleep(1);
		}
		close(dev_kstoreNVRAM);
		_exit(0);
	}
	return 0;
}
