#include "stdafx.h"

#ifndef LINELEN 
#define LINELEN 4096
#endif

char achStrUpChar[] = {			/* IBM Codepage 850	*/
	'\0', '\1', '\2', '\3', '\4', '\5', '\6', '\7',
	'\10', '\11', '\12', '\13', '\14', '\15', '\16', '\17',
	'\20', '\21', '\22', '\23', '\24', '\25', '\26', '\27',
	'\30', '\31', '\32', '\33', '\34', '\35', '\36', '\37',
	'\40', '\41', '\42', '\43', '\44', '\45', '\46', '\47',
	'\50', '\51', '\52', '\53', '\54', '\55', '\56', '\57',
	'\60', '\61', '\62', '\63', '\64', '\65', '\66', '\67',
	'\70', '\71', '\72', '\73', '\74', '\75', '\76', '\77',
	'\100', '\101', '\102', '\103', '\104', '\105', '\106', '\107',
	'\110', '\111', '\112', '\113', '\114', '\115', '\116', '\117',
	'\120', '\121', '\122', '\123', '\124', '\125', '\126', '\127',
	'\130', '\131', '\132', '\133', '\134', '\135', '\136', '\137',
	'\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
	'\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
	'\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
	'\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
	'\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
	'\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
	'\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
	'\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
	'\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
	'\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
	'\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
	'\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
	'\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
	'\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
	'\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377'
};

#define StrUpChar(c)	((char) achStrUpChar [(unsigned char) (c)])

static BOOL ReadLine(FILE *pf, char *pc, int MaxLen)
{
	if (!fgets(pc, MaxLen, pf)){
		*pc = 0x0;
		return (FALSE);
	}

	for (; *pc; pc++){
		if (!isprint((int)*pc)){
			*pc = ' ';
		}
	}
	return (TRUE);
}

void NormalizeString(char *s){
	int l, l2;

	l = strlen(s);
	while (l && (s[l - 1]) == ' '){
		s[--l] = 0x00;
	}
	for (l = 0; s[l] == ' '; l++);
	for (l2 = l; s[l2]; l2++){
		s[l2 - l] = s[l2];
	}
	s[l2 - l] = 0x0;
}

char *NormalizeStringUpCase(char *pszString){
	char *s = pszString;
	char *t = pszString;

	while ((s[0] == ' ') || (s[0] == '\t')) ++s;

	while ((*t++ = StrUpChar(*s++)) != 0){
		if ((s[0] == ' ') || (s[0] == '\t')){
			while ((s[1] == ' ') || (s[1] == '\t'))++s;
			if (s[1] == 0)++s;
		}
	}
	return(pszString);
}

static int StringIsEmpty(char *pc){
	if (!pc[0]){
		return 1;
	}
	for (; (*pc == ' ') || (*pc == '\t') || (*pc == '\r') || (*pc == '\n'); pc++);
	return (*pc = 0x0);
}

int Z_GetProfileString(const char *configFileName, const char *Section, const char *FieldName,
	char *Value, int MaxValueLen, BOOL NormalizeNames){
	FILE *cf;
	static char fn[512];
	char line[LINELEN + 1];
	char keyword[LINELEN + 1];
	char value[LINELEN + 1];
	char *pc;
	int LineNo = 0;
	int ret = 3;
	BOOL SectionFound = FALSE;
	

	*value = 0x00;
	if (!(cf = fopen(configFileName, "rt"))){
		LogEntry("Z_GetProfileString", "fopen error", -1, 1);
		ret = 2;
		goto ende;
	}

	while (ReadLine(cf, line, LINELEN)){
		LineNo++;
		if (line[0] == '['){
			pc = strchr(line, ']');
			if (pc){
				*pc = 0x0;
			}
			else{
				LogEntry("GetProfileString[]", "error", -1, 1);
			}
			if (NormalizeNames){
				NormalizeStringUpCase(&line[1]);
			}
			else{
				NormalizeString(&line[1]);
			}
			if (strcmp(&line[1], Section)){
				continue;
			}
			else{
				SectionFound = TRUE;
				ret = 4;
			}
		}
		else if (SectionFound && line[0] != '#'){
			pc = strchr(line, '=');
			if (pc){
				strncpy(keyword, line, pc - line);
				keyword[pc - line] = 0x0;
				if (NormalizeNames){
					NormalizeStringUpCase(keyword);
				}
				else{
					NormalizeString(keyword);
				}
				sscanf(++pc, "%s", value);
				if (!strcmp(keyword, FieldName)){
					strncpy(Value, pc, MaxValueLen);
					NormalizeString(Value);
					ret = 0;

					goto ende;
				}
				else if (!StringIsEmpty(line)){
					;
				}
			}
		}
	}

ende:
	if (cf){
		fclose(cf);
	}
	return  ret;
}

int GetConfigString(char *pSectionName, char* pFieldname, char **ppValue){
	char buff[512];
	int rv = 0;

	rv = Z_GetProfileString(CONFIGFILE, pSectionName, pFieldname, buff, 510, FALSE);
	if (rv != 0){
		VarLogEntry("Z_GetProfileString",
			"Reading config field '%s' from Section [%s] in file '%s' failed %s",
			rv, 0, pFieldname, pSectionName, CONFIGFILE, "≈‰÷√¥ÌŒÛ");
		return (5);
	}
	*ppValue = (char*)malloc(strlen(buff) + 1);
	strcpy(*ppValue, buff);
	return 0;
}

