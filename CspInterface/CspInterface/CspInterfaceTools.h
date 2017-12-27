#ifndef CSP_TOOL_H
#define CSP_TOOL_H
//是否记录日志	0.No 1.Yes
#define LOG_LEVEL 1
//日志文件大小
#define MAX_LOG_SIZE (2048*1024)
#define LINELEN 4096
#define LOGFILE "csp_zhuheng.log"
#define CONFIGFILE "csp_config_zhuheng.cfg"

//开启日志
void LogEntry(char *functionName, char *processDes, int rv, int level);

void VarLogEntry(char *functionName, char *processDes, int rv, int level,...);

//判断文件大小
unsigned long fileLength(char *fname);

//获得当前时间
char * GetTime(char *Buffer, int Len, const char *format);

int GetConfigString(char *pSectionName,char* pFieldname,char **ppValue);

int Z_GetProfileString(const char *configFileName,const char *Section,const char *FieldName,char *value,int MaxValueLen,BOOL NormalizeNames);

char *NormalizeStringUpCase(char *pszString);

void NormalizeString(char *s);

#endif