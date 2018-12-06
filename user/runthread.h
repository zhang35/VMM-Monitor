#ifndef RUNTHREAD_H
#define RUNTHREAD_H

#include <QThread>
#include <windows.h>
#include <winioctl.h>
#include "Ioctls.h"

class runthread : public QThread
{
    Q_OBJECT
public:
    explicit runthread(QObject *parent = 0);

    void run();
    void stop();

    bool  openWriteA();
    void  SetA(HANDLE hDevice);

    volatile bool stoprun;
private:
    HANDLE hDevice;
    unsigned long d_sharedM;
signals:
     void sendbuffer(unsigned char *buffer, unsigned long length);
public slots:

};

#endif // RUNTHREAD_H
