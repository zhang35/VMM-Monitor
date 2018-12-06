#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "mydriver.h"
#include <QMessageBox>
#include <QCloseEvent>
#include <QWidgetItem>
#include <iostream>
using namespace std;

const WCHAR* DRIVER_NAME = L"vmxcpu0";
const WCHAR* DRIVER_PATH = L"vmxcpu0.sys";
const WCHAR* DRIVER_NAME1 = L"WriteA";
const WCHAR* DRIVER_PATH1 = L"WriteA.sys";

const unsigned long d_sharedM = 0x7ffe0800;

MainWindow::MainWindow(QWidget *parent) :
        QMainWindow(parent),
        ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    initGui();
    init();
    sniffThread = new sniff_thread(this);
    sniffThread->start();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setBackGround(QString path)
{
    this->setAutoFillBackground(true);
    QPalette palette = this->palette();
    palette.setBrush(QPalette::Window,QBrush(QPixmap(path).scaled(
            this->size(),
            Qt::IgnoreAspectRatio,
            Qt::SmoothTransformation))); // 使用平滑的缩放方式

    this->setPalette(palette); // 至此, 已给widget加上了背景图.
}


void MainWindow::closeEvent(QCloseEvent *event)
{
    switch( QMessageBox::information(this,tr("提示"),tr("你确定要退出么?"),tr("确定"),tr("取消"),0,1))
    {
    case 0:
        {

            unloadDriver();
            event->accept();
            break;
        }
    case 1:event->ignore();//取消
        break;
    }
}

void MainWindow::initGui()
{
    this->setWindowTitle("Net Guard");
    ui->list_widget->hide();
    ui->doubt_widget->hide();
    ui->connection_widget->show();

    this->setFixedSize(900,550);
    this->setBackGround(":/images/icon/blue.png");

    //mouseMenu
    ui->connection_table->setContextMenuPolicy(Qt::CustomContextMenu);

    action_add_white = new QAction(this);
    action_add_white->setText(tr("添加信任"));

    action_add_black = new QAction(this);
    action_add_black->setText(tr("添加阻止"));

    mouseMenu = new QMenu(ui->connection_table);
    mouseMenu->addAction(action_add_white);
    mouseMenu->addAction(action_add_black);
}

bool MainWindow::initDriver()
{
    if (LoadNTDriver(DRIVER_NAME, DRIVER_PATH))
    {
        ui->statusBar->showMessage(tr("驱动加载成功！"), 3000);
    }
    else
    {
        ui->statusBar->showMessage(tr("错误，驱动加载失败！"), 3000);
        return false;
    }

    if ( LoadNTDriver(DRIVER_NAME1, DRIVER_PATH1) )
    {
        ui->statusBar->showMessage(tr("驱动WriteA加载成功！"), 3000);
    }
    else
    {
        ui->statusBar->showMessage(tr("错误，驱动WriteA加载失败！"), 3000);
        return false;
    }

    return true;
}

void MainWindow::initThread()
{
    thread = new runthread();

    if (!thread->openWriteA())
    {
        cout << "openWriteA() Error!" << endl;
        return;
    }
    cout << "openWriteA() Ok!" << endl;
    thread->start();
}

void MainWindow::initPacket()
{

}

void MainWindow::unloadDriver()
{

    if ( UnloadNTDriver(DRIVER_NAME) )
    {
        ui->statusBar->showMessage(tr("驱动卸载成功！"), 3000);
    }
    else
    {
        ui->statusBar->showMessage(tr("错误，驱动卸载失败！"), 3000);
    }

    if ( UnloadNTDriver(DRIVER_NAME1) )
    {
        ui->statusBar->showMessage(tr("驱动WriteA卸载成功！"), 3000);
    }
    else
    {
        ui->statusBar->showMessage(tr("错误，驱动WriteA卸载失败！"), 3000);
    }

    thread->stop();
}

void MainWindow::recvbuffer(unsigned char *buffer, unsigned long length)
{
            for (unsigned int i=0; i<length/2; i++)
            {
                cout << hex << *(USHORT *)(buffer+i) << endl;
            }
            cout <<  "data over$$$$$$$$$$$$$$$$$!!!!!!!!!!!!!!!!!" << endl;
  //  packet->sniff(buffer);
}

void MainWindow::on_action_load_triggered()
{
    if (initDriver())
    {
        initThread();
    }
}

void MainWindow::on_action_unload_triggered()
{
    unloadDriver();
}


void MainWindow::on_refreshButton_clicked()
{
   //    packet->print(packet_root);
  //  packet_root = get_packet_root();
   user_packet_root = get_user_packet_root();
  showPacket(user_packet_root);
    //print(user_packet_root);
}

void MainWindow::showPacket(PACKET_SAVE *user_packet_root)
{
    PACKET_SAVE *packetread = user_packet_root->next;
    PACKET_READ *packet = NULL;

    QString str;
    int i = 0;

    unsigned int count = get_packet_user_save_count();
    ui->connection_table->setRowCount(0);
    ui->connection_table->setRowCount(count);

    while (packetread != NULL)
    {
        packet = packetread->packet_read;

        str = macToString(packet->MAC_SRC);
        ui->connection_table->setItem(i, 0, new QTableWidgetItem(str));

        str = macToString(packet->MAC_DST);
        ui->connection_table->setItem(i, 1, new QTableWidgetItem(str));

        str = ipToString(packet->IP_SRC_ADDR);
        ui->connection_table->setItem(i, 2, new QTableWidgetItem(str));

        str = ipToString(packet->IP_DST_ADDR);
        ui->connection_table->setItem(i, 3, new QTableWidgetItem(str));

        switch(packet->protocol)
        {
        case 1:
            str = "ICMP";
            ui->connection_table->setItem(i, 4, new QTableWidgetItem(str));
            break;
        case 6:
            str = "TCP";
            ui->connection_table->setItem(i, 4, new QTableWidgetItem(str));
            break;
        case 17:
            str = "UDP";
            ui->connection_table->setItem(i, 4, new QTableWidgetItem(str));
            break;
        default:
            break;
        }

        str.setNum(packet->SRC_PORT);
        ui->connection_table->setItem(i, 5, new QTableWidgetItem(str));

        str.setNum(packet->DST_PORT);
        ui->connection_table->setItem(i, 6, new QTableWidgetItem(str));

        packetread = packetread->next;
        i++;
    }

}

QString MainWindow::ipToString(ulong ip)
{
    ulong temp32 = ntohl(ip);
    u_char *ch = (u_char *)&temp32;
    QString temp;
    QString str = "";

    for (int i=0; i<4; i++)
    {
        temp.setNum(*(ch+i));
        str += temp;
        if (i!=3)
        {
            str += '.';
        }
    }
    return str;
}

QString MainWindow::macToString(u_char *mac)
{
    QString temp;
    QString str = "";
    for(int i = 0; i < 6; i ++)
    {
        temp.setNum(*(mac + i), 16);
        if(temp == "0")
            str += "00";
        else
            str += temp;
        if(i != 5)
            str += ':';
    }
    return str;
}

void MainWindow::on_action_showConnection_triggered()
{
    ui->list_widget->hide();
    ui->doubt_widget->hide();
    ui->connection_widget->show();
}

void MainWindow::on_action_showList_triggered()
{
    ui->connection_widget->hide();
    ui->doubt_widget->hide();
    ui->list_widget->show();
}

void MainWindow::on_connection_table_customContextMenuRequested(QPoint pos)
{
    mouseMenu->exec(QCursor::pos());
}


void MainWindow::on_action_doubt_triggered()
{
    ui->list_widget->hide();
    ui->connection_widget->hide();
    ui->doubt_widget->show();
}
