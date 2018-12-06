#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include "runthread.h"
#include "sniff_thread.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QLabel *label;

    //mouse menu
    QMenu  *mouseMenu;
    QAction *action_add_white;
    QAction *action_add_black;

    void initGui();
    void setBackGround(QString path);
    bool initDriver();
    void initThread();
    void initPacket();
    void unloadDriver();
    void closeEvent(QCloseEvent *event);

    void showPacket(PACKET_SAVE *user_packet_root);
    QString ipToString(ulong ip);
    QString macToString(u_char *mac);


    runthread *thread;
    sniff_thread *sniffThread;
    PACKET_SAVE *user_packet_root;
private slots:
    void on_action_doubt_triggered();
    void on_connection_table_customContextMenuRequested(QPoint pos);
    void on_action_showList_triggered();
    void on_action_showConnection_triggered();
    void on_refreshButton_clicked();
    void on_action_unload_triggered();
    void on_action_load_triggered();

    void recvbuffer(unsigned char *buffer, unsigned long length);
};

#endif // MAINWINDOW_H
