// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             //  从 Windows 头文件中排除极少使用的信息
// Windows 头文件: 
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>
#include <wincrypt.h>
#include <winerror.h>
#include <errno.h>
#include <WinSock2.h>


// TODO:  在此处引用程序需要的其他头文件
#include "csp.h"
#include "mutex.h"
#include "log.h"
#include "cspService.h"
#include "common_util.h"
#include "config.h"
#include "regedit.h"
#include "sjl22_api.h"
#include "hsmcmd.h"
#include "hsm_com.h"
#include "hsmdefs.h"
#include "hsm_tcpsub.h"
#include "sjl22_api_zh.h"
#include "cspServiceImpl.h"
