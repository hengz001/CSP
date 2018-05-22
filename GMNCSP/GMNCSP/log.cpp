#include "stdafx.h"

static int LEVEL = 10;

void setLevel(int l){
	LEVEL = l;
}

int getLevel(void){
	return LEVEL;
}

void LogEntry(char *FunctionName, char *ProcessDesc, int rv, int level){
	FILE *log = NULL;
	
	if (level > LEVEL){
		return;
	}

	char timepad[4 + 2 + 2 + 2 + 2 + 2 + 1];
	GetTime(timepad, 4 + 2 + 2 + 2 + 2 + 2 + 1, "%Y%m%d%H%M%S");
	timepad[4 + 2 + 2 + 2 + 2 + 2] = 0;
	
	if (filelength(LOGFILE)>MAX_LOG_SIZE) {
		char filename[LEN_MAX_FNAME];

		lstrcpyA(filename, LOGFILE);
		lstrcpyA(filename + strlen(LOGFILE), timepad);
		remove(filename);
		rename(LOGFILE, filename);
	}

	log = fopen(LOGFILE, "a");
	if (log == NULL) {

		return;
	}

	FunctionName = (FunctionName == NULL) ? "(NULL)" : FunctionName;
	ProcessDesc = (ProcessDesc == NULL) ? "(NULL)" : ProcessDesc;

	fprintf(log, "[0x%08X]", getpid());
	fprintf(log, "/* %s()", FunctionName);
	fprintf(log, ": %s ", ProcessDesc);
	fprintf(log, "(%d) */", rv);
	fprintf(log, " [%s] \n", timepad);
	
	fclose(log);
}

void VarLogEntry(char *FunctionName, char *ProcessDesc, int rv, int level, ...){
	va_list params;
	char tmp[4096];
	va_start(params, level);
	vsprintf(tmp, ProcessDesc, params);
	va_end(params);

	LogEntry(FunctionName, tmp, rv, level);
}
