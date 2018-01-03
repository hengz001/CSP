#ifndef MUTEX_H
#define MUTEX_H


typedef int(*CSP_CREATEMUTEX)(void ** ppMutex);

typedef int(*CSP_DESTROYMUTEX)(void * pMutex);

typedef int(*CSP_LOCKMUTEX)(void * pMutex);

typedef int (*CSP_UNLOCKMUTEX)(void * pMutex);

typedef struct CSP_MUTEX_FUNCTION_LIST{
	CSP_CREATEMUTEX pCreateMutex;
	CSP_DESTROYMUTEX pDestroyMutex;
	CSP_LOCKMUTEX pLockMutex;
	CSP_UNLOCKMUTEX pUnlockMutex;
}CSP_MUTEX_FUNCTION_LIST, *PCSP_MUTEX_FUNCTION_LIST;

/*
int CSP_I_CreateMutex(void ** ppMutex);

int CSP_I_DestroyMutex(void ** ppMutex);

int CSP_I_LockMutex(void ** ppMutex);

int CSP_I_UnlockMutex(void ** ppMutex);
*/

int CSP_SetMutexFunction(void);

int CSP_CreateMutex(void);

int CSP_DestroyMutex(void);

int CSP_LockMutex(void);

int CSP_UnlockMutex(void);

int CSP_InitMutex(void);

int CSP_Destroy_Mutex(void);


int getMutexFlag(void);

#endif