#ifndef SNIFF_THREAD_H
#define SNIFF_THREAD_H

#include <QThread>
#include "my_packet.h"

class sniff_thread : public QThread
{
    Q_OBJECT
public:
    explicit sniff_thread(QObject *parent = 0);

    void run();
    void stop();

    volatile bool stoprun;

signals:

public slots:

};

#endif // SNIFF_THREAD_H
