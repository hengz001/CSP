#include "mgrSvr.h"

void hsmDaemon(int debug)
{
	int bg;

	if(!debug)
	{
		if((bg=fork()) < 0){
			exit(0);
		}else if(bg > 0){
			exit(0);
		}
		//0:STDIO  1:STDOUT  2:STDERR
		close(0);
		close(1);
		close(2);
		setpgid(0,getpid());
		setpgrp();
		setsid();
	}
}
