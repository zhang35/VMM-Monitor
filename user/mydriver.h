#ifndef MYDRIVER_H
#define MYDRIVER_H

#include <windows.h>

bool LoadNTDriver(const WCHAR* lpszDriverName, const WCHAR* lpszDriverPath);
bool UnloadNTDriver(const WCHAR*  szSvrName );


#endif // MYDRIVER_H
