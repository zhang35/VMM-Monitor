#ifndef MY_PACKET_H
#define MY_PACKET_H

#include "pcap.h"
#define HAVE_REMOTE

#include "my_packet_head.h"


int getpacket();								//�û�̬ץ��
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);//�û�̬��ʼ�������ݰ�
void sniff(unsigned char *pBuffer);				//��ʼ�����ں�̬��̽��������

void init();

PACKET_SAVE *get_packet_root();					//��ȡ�ں�̬����ָ��
PACKET_SAVE *get_user_packet_root();//��ȡ�û�̬����ָ��
unsigned int get_packet_user_save_count();

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


#endif // MY_PACKET_H
