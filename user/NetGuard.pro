#-------------------------------------------------
#
# Project created by QtCreator 2012-04-25T14:49:51
#
#-------------------------------------------------

QT       += core gui

TARGET = NetGuard
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    mydriver.cpp \
    runthread.cpp \
    my_packet.cpp \
    sniff_thread.cpp

HEADERS  += mainwindow.h \
    mydriver.h \
    Ioctls.h \
    runthread.h \
    my_packet.h \
    my_packet_head.h \
    sniff_thread.h

FORMS    += mainwindow.ui

CONFIG       += console thread
LIBS += -l wpcap
LIBS += -l Packet

LIBS += -l ws2_32

RESOURCES += \
    images.qrc
