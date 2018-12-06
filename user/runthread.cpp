#include "runthread.h"

#include <iostream>
using namespace std;

runthread::runthread(QObject *parent) :
    QThread(parent)
{
   stoprun=false;
   d_sharedM = 0x7ffe0800;
}

bool runthread::openWriteA()
{
    hDevice =
            CreateFile(L"\\\\.\\WriteA",
            GENERIC_READ | GENERIC_WRITE,
            0,		// share mode none
            NULL,	// no security
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL );		// no template

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        cout << "Failed to obtain file handle to device: "
               "%s with Win32 error code:" << GetLastError() << endl;
        return false;
    }
    return true;
}

void runthread::SetA(HANDLE hDevice)
{
    UCHAR InputBuffer[10];
    UCHAR OutputBuffer[10];
    //将输入缓冲区全部置成0XBB
    memset(InputBuffer,0xBB,10);
    DWORD dwOutput;
    //输入缓冲区作为输入，输出缓冲区作为输出
    BOOL bRet;
    bRet = DeviceIoControl(hDevice, IOCTL_NG, InputBuffer, 10, &OutputBuffer, 10, &dwOutput, NULL);

    if (bRet)
    {
        cout << "SetA Ok\n" ;
    }
    else
    {
          cout << "EEEE\n" ;
    }
    return;
}

void runthread::stop()
{
    stoprun=true;
    CloseHandle(hDevice);
}

void runthread::run()
{
    stoprun = false;

    unsigned char *p = (unsigned char *)d_sharedM;
    unsigned long pktLength = 0;

    SetA(hDevice);

    while (!stoprun)
    {
        if (*p != 'Z')
        {
            continue;
        }

        pktLength = *(unsigned short*)(p+1);
        u_char *buffer = new u_char[pktLength];
        memcpy(buffer, p+3, pktLength);

//        for (int i=0; i<pktLength/2; i++)
//        {
//            cout << hex << *(USHORT *)(buffer+i) << endl;
//        }
//        cout <<  "data over$$$$$$$$$$$$$$$$$!!!!!!!!!!!!!!!!!" << endl;

        SetA(hDevice);

        sendbuffer(buffer, pktLength);
    }
}
