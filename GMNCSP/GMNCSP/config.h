
static BOOL ReadLine(FILE *pf, char *pc, int MaxLen);

void NormalizeString(char *s);

char *NormalizeStringUpCase(char *pszString);

static int StringIsEmpty(char *pc);

int Z_GetProfileString(const char *configFileName, const char *Section, const char *FieldName,
	char *Value, int MaxValueLen, BOOL NormalizeNames);

int GetConfigString(char *pSectionName, char* pFieldname, char **ppValue);