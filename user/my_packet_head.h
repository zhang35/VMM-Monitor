#ifndef MY_PACKET_HEAD_H
#define MY_PACKET_HEAD_H

#include <pcap.h>

struct TCP_HEAD									//TCP首部
{
        unsigned short srcPort;
        unsigned short dstPort;
        unsigned int seq;
        unsigned int ack;
        unsigned char hlen;
        unsigned char flags;
        unsigned short winsiz;
        unsigned short checksum;
        unsigned short urgPointer;
};

struct UDP_HEAD									//UDP首部
{
        unsigned short srcPort;
        unsigned short dstPort;
        unsigned short length;
        unsigned short checksum;
};

struct IP_HEAD									//IP首部
{
        unsigned char VAI;
        unsigned char TOS;
        unsigned short tlen;
        unsigned short iden;
        unsigned short fragment;
        unsigned char TTL;
        unsigned char protocol;
        unsigned short checksum;
        unsigned int srcAddr;
        unsigned int dstAddr;
};

struct MAC_HEAD									//以太帧首部
{
        unsigned char mac_srcaddr[6];
        unsigned char mac_dstaddr[6];
        unsigned short type;
};

struct hole										//所需重组的IP包的链表
{
        unsigned short first;
        unsigned short last;
        hole *next;
};

struct re_head									//每一个正在重组的IP包的链表
{
        IP_HEAD *iphead;
        hole *le;
        unsigned char ip[7000];
        re_head *next;
        unsigned short len;
};

struct PACKET_READ								//存放每一个连接所需信息结构体
{
        unsigned char MAC_SRC[6];
        unsigned char MAC_DST[6];
        unsigned int IP_SRC_ADDR;
        unsigned int IP_DST_ADDR;
        unsigned char protocol;
        unsigned short SRC_PORT;
        unsigned short DST_PORT;
        unsigned int SEQ;
        unsigned int ACK;
        unsigned short TCP_DATA_LEN;
};

struct PACKET_SAVE								//存放连接数据信息链表结构体
{
        unsigned int count;
        PACKET_READ *packet_read;
        PACKET_SAVE *next;
};

struct ILLEAGAL_HEAD							//TCP伪首部，用来计算TCP首部校验和
{
        unsigned int SRC_ADDR;
        unsigned int DST_ADDR;
        unsigned char RESERVE;
        unsigned char PROTOCOL;
        unsigned short LEN;
};



#endif // MY_PACKET_HEAD_H
