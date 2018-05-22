#include "stdafx.h"

CSP_MUTEX_FUNCTION_LIST csp_mutex_function_list;
static int MutexInitFlag = 0;
void *g_pMutex;

int CSP_I_CreateMutex(void ** ppMutex){
	LPCRITICAL_SECTION lpCriticalSection;

	lpCriticalSection = (LPCRITICAL_SECTION)malloc(sizeof (CRITICAL_SECTION));
	if (lpCriticalSection == NULL)
	{
		SetLastError(NTE_NO_MEMORY);
		return 1;
	}

	InitializeCriticalSection(lpCriticalSection);
	*ppMutex = (void *)lpCriticalSection;
	return 0;
}

int CSP_I_DestroyMutex(void * pMutex){
	 LPCRITICAL_SECTION lpCriticalSection;
	
    if (pMutex == NULL)
    {
        return 0;
    }
	
	lpCriticalSection = (LPCRITICAL_SECTION)pMutex;
	
	DeleteCriticalSection(lpCriticalSection);
	
	free(pMutex);
	pMutex = NULL;
	
    return 0;
}

int CSP_I_LockMutex(void * pMutex){
	LPCRITICAL_SECTION lpCriticalSection;

	if (pMutex == NULL)
	{
		return 0;
	}
	lpCriticalSection = (LPCRITICAL_SECTION)pMutex;

	EnterCriticalSection(lpCriticalSection);

	return 0;
}

int CSP_I_UnlockMutex(void * pMutex){
	LPCRITICAL_SECTION lpCriticalSection;
	if (pMutex == NULL)
	{
		return 0;
	}
	lpCriticalSection = (LPCRITICAL_SECTION)pMutex;

	LeaveCriticalSection(lpCriticalSection);

	return 0;
}

int CSP_SetMutexFunction(void){
	csp_mutex_function_list.pCreateMutex = &CSP_I_CreateMutex;
	csp_mutex_function_list.pDestroyMutex = &CSP_I_DestroyMutex;
	csp_mutex_function_list.pLockMutex = &CSP_I_LockMutex;
	csp_mutex_function_list.pUnlockMutex = &CSP_I_UnlockMutex;
	return 0;
}

int CSP_CreateMutex(void){
	return csp_mutex_function_list.pCreateMutex(&g_pMutex);
}

int CSP_DestroyMutex(void){
	return csp_mutex_function_list.pDestroyMutex(g_pMutex);
}

int CSP_LockMutex(void){
	return csp_mutex_function_list.pLockMutex(g_pMutex);
}

int CSP_UnlockMutex(void){
	return csp_mutex_function_list.pUnlockMutex(g_pMutex);
}

int CSP_InitMutex(void)
{
	int rv;

	if (MutexInitFlag == 0)
	{
		rv = CSP_SetMutexFunction();
		if (rv != 0)
		{
			return rv;
		}
		rv = CSP_CreateMutex();
		if (rv != 0)
		{
			return rv;
		}
		MutexInitFlag = 1;
	}
	return 0;
}


int CSP_Destroy_Mutex(void)
{
	int rv;
	rv = CSP_DestroyMutex();
	g_pMutex = NULL;
	MutexInitFlag = 0;
	return 0;
}

int getMutexFlag(void){
	return MutexInitFlag;
}
