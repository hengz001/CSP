#include "tcpSvr.h"

int ChangeNet(char *IP, char *MASK, char *BROADCAST,char *ROUTE, char *devname)
{
	char Command[255];
	char Param1[20],Param2[20],Param3[20];
	int status;
	pid_t pid;

	strcpy(Command,"ifconfig");
	strcpy(Param1,devname);
	strcpy(Param2,"netmask");
	strcpy(Param3,"broadcast");

	pid = fork();
	if(pid == 0){
		if((IP!=NULL) && (MASK!=NULL) && (BROADCAST!=NULL)){
			execl("/sbin/ifconfig",Command,Param1,IP,Param2,MASK,Param3,BROADCAST,NULL);
		}
		if((IP!=NULL) && (MASK!=NULL) && (BROADCAST==NULL)){
			execl("/sbin/ifconfig",Command,Param1,IP,Param2,MASK,NULL);
		}
		if((IP!=NULL) && (MASK==NULL) && (BROADCAST==NULL)){
			execl("/sbin/ifconfig",Command,Param1,IP,NULL);
		}
		if((IP==NULL) && (MASK!=NULL) && (BROADCAST!=NULL)){
			execl("/sbin/ifconfig",Command,Param1,Param2,MASK,Param3,BROADCAST,NULL);
		}
		if((IP==NULL) && (MASK!=NULL) && (BROADCAST==NULL)){
			execl("/sbin/ifconfig",Command,Param1,Param2,MASK,NULL);
		}
		if((IP==NULL) && (MASK==NULL) && (BROADCAST!=NULL)){
			execl("/sbin/ifconfig",Command,Param1,Param3,BROADCAST,NULL);
			}
		if((IP!=NULL) && (MASK==NULL) && (BROADCAST!=NULL)){
			execl("/sbin/ifconfig",Command,Param1,IP,Param3,BROADCAST,NULL);
		}
		exit(0);
	}
	waitpid(pid,&status,0);

	if(ROUTE!=NULL){
		strcpy(Command,"route");
		strcpy(Param1,"add");
		strcpy(Param2,"default");
		strcpy(Param3,"gw");
		pid = fork();
		if(pid==0){
			execl("/sbin/route",Command,Param1,Param2,Param3,ROUTE,NULL);
			exit(0);
		}
		waitpid(pid,&status,0);
	}

	return 0;
}
