#ifndef MY_PACKET_HEAD_H
#define MY_PACKET_HEAD_H

#include <pcap.h>

struct TCP_HEAD									//TCP�ײ�
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

struct UDP_HEAD									//UDP�ײ�
{
        unsigned short srcPort;
        unsigned short dstPort;
        unsigned short length;
        unsigned short checksum;
};

struct IP_HEAD									//IP�ײ�
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

struct MAC_HEAD									//��̫֡�ײ�
{
        unsigned char mac_srcaddr[6];
        unsigned char mac_dstaddr[6];
        unsigned short type;
};

struct hole										//���������IP��������
{
        unsigned short first;
        unsigned short last;
        hole *next;
};

struct re_head									//ÿһ�����������IP��������
{
        IP_HEAD *iphead;
        hole *le;
        unsigned char ip[7000];
        re_head *next;
        unsigned short len;
};

struct PACKET_READ								//���ÿһ������������Ϣ�ṹ��
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

struct PACKET_SAVE								//�������������Ϣ����ṹ��
{
        unsigned int count;
        PACKET_READ *packet_read;
        PACKET_SAVE *next;
};

struct ILLEAGAL_HEAD							//TCPα�ײ�����������TCP�ײ�У���
{
        unsigned int SRC_ADDR;
        unsigned int DST_ADDR;
        unsigned char RESERVE;
        unsigned char PROTOCOL;
        unsigned short LEN;
};



#endif // MY_PACKET_HEAD_H
