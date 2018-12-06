#ifndef PACKET_H
#define PACKET_H

#include "iostream"
#include "pcap.h" 
#define HAVE_REMOTE


using namespace std;

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
//	unsigned short type;
	unsigned int IP_SRC_ADDR;
	unsigned int IP_DST_ADDR;
	unsigned char protocol;
	unsigned short SRC_PORT;
	unsigned short DST_PORT;
	unsigned int SEQ;
	unsigned int ACK;
	unsigned short TCP_DATA_LEN;
//	PACKET_READ *next;
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

PACKET_SAVE *get_packet_root();

void sniff(unsigned char *pBuffer);				//��ʼ������̽��������

//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
PACKET_READ *frame(unsigned char *pBuffer, PACKET_READ *packet_read_temp);
void MAC(unsigned char *pBuffer);

PACKET_READ *ip_solve(unsigned char *pBuffer, PACKET_READ *packet_temp);
re_head *ip_recombine(unsigned char *pBuffer, unsigned short length);
void ipadd(unsigned int add);

PACKET_READ *tcp_solve(unsigned char *pBuffer, unsigned short length, PACKET_READ *packet_temp);
PACKET_READ *udp_solve(unsigned char *pBuffer, unsigned short length, PACKET_READ *packet_temp);

//void print_packet(PACKET_READ *packet_temp);
void print(PACKET_SAVE *packet_temp);

/*
void create_packet();

void send();
PACKET_SAVE *get_packet_root();
pcap_t *get_adhandle(); 
unsigned char *tcp_create(PACKET_SAVE *packet_root);
char *ip_create(PACKET_READ *read, char *puffer, unsigned short len);
char *frame_creat(PACKET_READ *read, char *pBuffer, unsigned short len);

unsigned short tcp_head_checksum(PACKET_READ *read, unsigned short len);
unsigned short headchecksum(char *pBuffer, unsigned short len);
*/
#endif
