#include "stdafx.h"

static	char *logFile = "csp.log";

void LogEntry(char *functionName, char *processDes, int rv, int level){
	FILE *log = NULL;
	
	//是否记录log
	if (!level || LOG_LEVEL == 0){
		return ;
	}

	//当前时间
	char fileName[MAX_PATH];
	char timePad[4+2+2+2+2+2+1];
	GetTime(timePad,sizeof(timePad),"%Y%m%d%H%M%S");
	timePad[4+2+2+2+2+2] = 0;
	
	//读取日志文件
	if (fileLength(logFile)>MAX_LOG_SIZE){
		strcpy(fileName,logFile);
		strcpy(fileName+sizeof(logFile),timePad);

		remove(fileName);
		rename(logFile,fileName);
	}

	//日志文件
	log = fopen(logFile, "a");
	if (NULL == log){
		return;
	}

	functionName = (NULL == functionName) ? "NULL" : functionName;
	processDes = (NULL == processDes) ? "NULL" : processDes;

	fprintf(log,"[0x%08X]",_getpid());
	fprintf(log,"/* %s()",functionName);
	fprintf(log," %s ",processDes);
	fprintf(log, "(%d) %s */\n", rv, timePad);
	
	fclose(log);
	return;
}

unsigned long fileLength(char *fname){
	HFILE handle;
	long start, end;

	//判断文件开始 and 结束	
	handle = _lopen(fname,OF_READ);
	start = _llseek(handle,0L,SEEK_SET);
	end = _llseek(handle,0L,SEEK_END);
	_lclose(handle);
	return (end-start);
}

char * GetTime(char *Buffer, int Len, const char *format){
	time_t clock;
	clock = time((time_t)0);
	strftime(Buffer, Len, format, localtime(&clock));
	return (Buffer);
}