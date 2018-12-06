#include "packet.h"

PACKET_SAVE *packet_root = new PACKET_SAVE;		//�������������Ϣ����
unsigned int packet_save_count = 0;				//����������¼���Ӹ���

re_head *root = new re_head;					//�������ip������
int root_flag = 1;

/***********************������̽��������*************************/
void sniff(unsigned char *pBuffer)
{
	PACKET_READ *packet_read_temp = new PACKET_READ;					//���ÿһ�����ݰ���Ҫ������
	PACKET_SAVE *pre_save, *save = new PACKET_SAVE;				

	packet_read_temp = frame(pBuffer, packet_read_temp);					//��ʼ��������ÿһ�����ݰ�������Ҫ�����ݴ����packet_temp��

	if(packet_read_temp != 0)												//�������Ľ�����н�һ������
	{

		save->packet_read = packet_read_temp;
		save->count = packet_save_count;
		save->next = NULL;
		if(packet_save_count == 0)
		{
			packet_root->next = save;
			packet_save_count ++;
		}
		else
		{
			pre_save = packet_root;
			while(pre_save->next != NULL)
			{
				if(pre_save->next->packet_read->IP_DST_ADDR == packet_read_temp->IP_DST_ADDR		//���������ӽ��и���
					&& pre_save->next->packet_read->IP_SRC_ADDR == packet_read_temp->IP_SRC_ADDR
					&& pre_save->next->packet_read->DST_PORT == packet_read_temp->DST_PORT
					&& pre_save->next->packet_read->SRC_PORT == packet_read_temp->SRC_PORT)
				{
					pre_save->next->packet_read->ACK = packet_read_temp->ACK;
					pre_save->next->packet_read->SEQ = packet_read_temp->SEQ;
					pre_save->next->packet_read->TCP_DATA_LEN = packet_read_temp->TCP_DATA_LEN;
					break;
				}
				pre_save = pre_save->next;
			}
			if(pre_save->next == NULL)												//���µ����������
			{
				pre_save->next = save;
				packet_save_count ++;
			}
		}
	}
}
/*************************************************************************/

/**************************����̫��֡�ײ����д���*************************/
PACKET_READ *frame(unsigned char *pBuffer, PACKET_READ *packet_read_temp)
{
	unsigned char *temp;
	unsigned short type;
	int i;
	temp = pBuffer;
	type = ntohs(*(unsigned short *)(temp + 12));

	for(i = 0; i < 6; i++)
		packet_read_temp->MAC_DST[i] = *(unsigned char *)(temp + i);
	for(i = 0; i < 6; i++)
		packet_read_temp->MAC_SRC[i] = *(unsigned char *)(temp + 6 + i);
	
	if(type != 0x0800)
		return 0;																	//�������IPv4��������0
	else																			//�����IPv4������ʼ����
		return ip_solve(pBuffer + 14, packet_read_temp);
}
/*************************************************************************/

/*****************************����IP�ײ�**********************************/
PACKET_READ *ip_solve(unsigned char *pBuffer, PACKET_READ *packet_read_temp)
{
	IP_HEAD *ip_head;
	re_head *longip;																//��Ҫ�����IPv4��
	longip = 0;
	unsigned char *temp;
	unsigned char IHL, flag, MF;
	unsigned short offset;
	unsigned short length;															//IP���ܳ���
	temp = pBuffer;
	ip_head = (IP_HEAD *)pBuffer;

	packet_read_temp->IP_DST_ADDR = ntohl(ip_head->dstAddr);
	packet_read_temp->IP_SRC_ADDR = ntohl(ip_head->srcAddr);
	packet_read_temp->protocol = ip_head->protocol;

	IHL = ip_head->VAI & 15;
	length = ntohs(ip_head->tlen);

	flag = (*(temp + 6))>>5;
	MF = flag & 1;

	offset = ntohs(ip_head->fragment) & 0x1fff;
	if(MF == 1 || offset != 0)														//��Ҫ����
	{
		longip = ip_recombine(pBuffer, length);
		if(longip == 0)																//δ������
			return 0;
	}
	if(!longip)																		//����Ҫ����
	{
		switch(ip_head->protocol)
		{
		case 6:
			packet_read_temp = tcp_solve(pBuffer + (IHL * 4), length - (IHL * 4), packet_read_temp);
			break;
		case 17:
			packet_read_temp = udp_solve(pBuffer + (IHL * 4), length - (IHL * 4), packet_read_temp);
			break;
		default:
			cout<<endl;
			break;
		}
	}
	else																			//����õ�IP��
	{
		IHL = longip->iphead->VAI & 15;
		switch(longip->iphead->protocol)
		{
		case 6:
                        packet_read_temp = tcp_solve((unsigned char *)longip->iphead + (IHL * 4), longip->len - (IHL * 4), packet_read_temp);
			break;
		case 17:
                        packet_read_temp = udp_solve((unsigned char *)longip->iphead + (IHL * 4), longip->len - (IHL * 4), packet_read_temp);
			break;
		default:
			break;
		}
	}
	return packet_read_temp;
}
/*************************************************************************/

/************************�Է�Ƭ��IP����������*****************************/
re_head *ip_recombine(unsigned char *pBuffer, unsigned short length)
{
	IP_HEAD *temp;
	re_head *p, *q;
	unsigned char IHL, flag, MF;
	unsigned short offset;
	int i = 0, first, last;
	hole *l, *hp, *ad;
	ad = new hole;

	temp = (IP_HEAD *)pBuffer;
	if(root_flag)
		root->next = NULL;
	p = root->next;
	q = root;
		
	IHL = temp->VAI & 15;
	flag = (*(pBuffer + 6))>>5;
	MF = flag & 1;
	offset = ntohs(temp->fragment) & 0x1fff;
	first = offset * 8;
	last = first + (length - (IHL * 4)) - 1;
	while(p != 0)
	{	
		if(temp->iden == p->iphead->iden)
		{
			hp = p->le;
			l = hp->next;
			while(l->last < first - 1)
			{
				hp = l;
				l = l->next;
			}
			if(l->first == first)
				l->first = last + 1;
			else
			{
				ad->first = last + 1;
				ad->last = l->last;
				ad->next = l->next;
				l->last = first - 1;
				l->next = ad;
				hp = l;
				l = l->next;
			}
			memcpy(p->ip + first, pBuffer + (IHL * 4), length - (IHL * 4));
			if(ad->first > ad->last || MF == 0)
			{
				hp->next = NULL;
				free(l);
				if(MF == 0)
					p->len = last + 1;
			}
			if(p->le->next == NULL)
			{
	//			if(q != root)
					q->next = p->next;
				p->next = NULL;
				return p;
			}
			return 0;
		}
		q = p;
		p = p->next;
	}
	root->next = new re_head;
	root->next->iphead = temp;
	root->next->le = new hole;
	root_flag = 0;
	memcpy(root->ip + first, pBuffer + (IHL * 4), length - (IHL * 4));
	if(first != 0)
	{
		root->next->le->next = new hole;
		root->next->le->next->first = 0;
		root->next->le->next->last = first - 1;
		ad->first = last + 1;
		ad->last = 6999;
		ad->next = NULL;
		root->next->le->next->next = ad;
	}
	else
	{
		ad->first = last + 1;
		ad->last = 6999;
		ad->next = NULL;
		root->next->le->next = ad;
	}
	root->next->len = 7000;
	root->next->next = NULL;
	return 0;
}
/*************************************************************************/

/******************************����TCP�ײ�*******************************/
PACKET_READ *tcp_solve(unsigned char *pBuffer, unsigned short length, PACKET_READ *packet_read_temp)
{
	TCP_HEAD *tcp_head;
	tcp_head = (TCP_HEAD *)pBuffer;
	char SYN;
	SYN = tcp_head->flags & 0x02;
	packet_read_temp->DST_PORT = ntohs(tcp_head->dstPort);
	packet_read_temp->SRC_PORT = ntohs(tcp_head->srcPort);
	packet_read_temp->SEQ = ntohl(tcp_head->seq);
	packet_read_temp->ACK = ntohl(tcp_head->ack);
	if(SYN == 2)
		packet_read_temp->TCP_DATA_LEN = length - (tcp_head->hlen >> 4) * 4 + 1;
	else
		packet_read_temp->TCP_DATA_LEN = length - (tcp_head->hlen >> 4) * 4;
	return packet_read_temp;
}
/*************************************************************************/

/******************************����UDP�ײ�********************************/
PACKET_READ *udp_solve(unsigned char *pBuffer, unsigned short length, PACKET_READ *packet_read_temp)
{
	UDP_HEAD *udp_head;
	udp_head = (UDP_HEAD *)pBuffer;
	packet_read_temp->DST_PORT = ntohs(udp_head->dstPort);
	packet_read_temp->SRC_PORT = ntohs(udp_head->srcPort);
	return packet_read_temp;
}
/*************************************************************************/

/*
void print_packet(PACKET_READ *packet_read_temp)
{
//	PACKET_READ *s = new PACKET_READ;
//	s = packet_read_root->next;
//	while(s != NULL)
//	{
		printf("\nEthernet frame :\ndestination Physical Address : ");
		MAC(packet_read_temp->MAC_DST);
		printf("source Physical Address : ");
		MAC(packet_read_temp->MAC_SRC);

		cout<<"source ip:";
		ipadd(packet_read_temp->IP_SRC_ADDR);
		cout<<"destination ip:";
		ipadd(packet_read_temp->IP_DST_ADDR);

		switch(packet_read_temp->protocol)
		{
		case 6:
			cout<<"TCP :("<<(int)packet_read_temp->protocol<<")"<<endl;
			break;
		case 17:
			cout<<"UDP :("<<(int)packet_read_temp->protocol<<")"<<endl;
			break;
		default:
			break;
		}
		cout<<"source port : "<<s->SRC_PORT<<endl;
		cout<<"destination port : "<<s->DST_PORT<<endl;

//		packet_read_temp = packet_read_temp->next;
//	}
}
*/

/*******************************��ӡ������Ϣ******************************/
void print(PACKET_SAVE *packet_read_temp)
{
	while(packet_read_temp->next != NULL)
	{
		packet_read_temp = packet_read_temp->next;
		cout<<packet_read_temp->count;
		printf("\nEthernet frame :\ndestination Physical Address : ");
		MAC(packet_read_temp->packet_read->MAC_DST);
		printf("source Physical Address : ");
		MAC(packet_read_temp->packet_read->MAC_SRC);

		cout<<"source ip:";
		ipadd(packet_read_temp->packet_read->IP_SRC_ADDR);
		cout<<"destination ip:";
		ipadd(packet_read_temp->packet_read->IP_DST_ADDR);

		switch(packet_read_temp->packet_read->protocol)
		{
		case 6:
                        cout<<"TCP :("<<(int)packet_read_temp->packet_read->protocol<<")"<<endl;
			break;
		case 17:
                        cout<<"UDP :("<<(int)packet_read_temp->packet_read->protocol<<")"<<endl;
			break;
		default:
			break;
		}
                cout<<"source port : "<<packet_read_temp->packet_read->SRC_PORT<<endl;
                cout<<"destination port : "<<packet_read_temp->packet_read->DST_PORT<<endl;
	}
}
/*************************************************************************/

/****************************��ӡMAC��ַ**********************************/
void MAC(unsigned char *pBuffer)
{
	unsigned char *b;
	b = (unsigned char *)pBuffer;
	for(int i = 0; i < 6; i++)
	{
		printf("%x", *b);
		if(i != 5)
			printf(":");
		else
			printf("\n");
		b = b + 1;
	}
}
/*************************************************************************/

/******************************��ӡIP��ַ*********************************/
void ipadd(unsigned int add)
{
	unsigned int address;
	address = ntohl(add);
	unsigned char *b;
	b = &(unsigned char &)address;
	for(int i = 0; i < 4; i++)
	{
		cout<<(unsigned int)*b;
		if(i != 3)
			cout<<".";
		else
			cout<<endl;
		b = b + 1;
	}
	return;
}
/*************************************************************************/
/*
void create_packet()
{
	tcp_create(packet_root);
}
*/

PACKET_SAVE *get_packet_root()
{
    return packet_root;
}
