#include "sniff_thread.h"

sniff_thread::sniff_thread(QObject *parent) :
        QThread(parent)
{
    stoprun = false;
}

void sniff_thread::stop()
{
    stoprun=true;
}

void  sniff_thread::run()
{
    getpacket();
}
