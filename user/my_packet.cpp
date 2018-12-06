#include "my_packet.h"
#include <iostream>
using namespace std;

PACKET_SAVE *packet_root;		//����ں�̬����������Ϣ����
unsigned int packet_save_count = 0;				//����������¼�ں�̬���Ӹ���

PACKET_SAVE *packet_user_root;		//����ں�̬����������Ϣ����
unsigned int packet_user_save_count = 0;				//����������¼�ں�̬���Ӹ���

re_head *root;					//�������ip������
int root_flag = 1;								//��־��1��ʾû�и����Ϊ��

void init()
{
    packet_root = new PACKET_SAVE;		//����ں�̬����������Ϣ����
    memset(packet_root, 0, sizeof(PACKET_SAVE));
    packet_save_count = 0;				//����������¼�ں�̬���Ӹ���

    packet_user_root = new PACKET_SAVE;		//����û�̬����������Ϣ����
    memset(packet_user_root, 0, sizeof(PACKET_SAVE));
    packet_user_save_count = 0;				//����������¼�û�̬���Ӹ���

    root = new re_head;					//�������ip������
    memset(root, 0, sizeof(re_head));
    root_flag = 1;
}

/**************************�û�̬ץ��****************************/
int getpacket()
{
        pcap_t *adhandle;
        pcap_if_t *alldevs;
        pcap_if_t *d;
        int inum;
        int i=0;

        char errbuf[PCAP_ERRBUF_SIZE];
        u_int netmask;

        struct bpf_program fcode;
        /*���ü�������*/
        //SetIpsort(packet_filter,4);

        /* ����豸�б� */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
        }

        /* ����б� */
        for(d=alldevs;d;d=d->next)
        {
                printf("%d. %s", ++i, d->name);
                if (d->description)
                printf(" (%s)\n", d->description);
                else
                /* Y- û����Ч������ */
                printf(" (No description available)\n");
        }


        if(i==0)
        {
                printf("nNo interfaces found! Make sure WinPcap is installed.n");
                return -1;
        }

//        printf("Enter the interface number (1-%d):",i);
//        scanf("%d", &inum);

//        if(inum < 1 || inum > i)
//        {
//                printf("\nInterface number out of range.\n");
//                /* �ͷ��豸�б� */
//                pcap_freealldevs(alldevs);
//                return -1;
//        }

        inum = 1;
        /* ��ת����ѡ�豸 */
        for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

        printf("%s",inet_ntoa(((struct sockaddr_in*)(d->addresses->addr))->sin_addr));
        /* �������� */
        if ((adhandle= pcap_open_live(d->name, //�豸��
                65536, // ��׽���������ݰ�
                0, // ����ģʽ //���ģʽ 1 �򿪻��ģʽ 0�رջ��ģʽ
                1000, // ���볬ʱ
                errbuf // ���󻺳�
                )) == NULL)
        {
                /* Y- ��ʧ��*/
                fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
                /* �ͷ��б� */
                pcap_freealldevs(alldevs);
                return -1;
        }

        /* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
        if(pcap_datalink(adhandle) != DLT_EN10MB)
        {
                fprintf(stderr,"nThis program works only on Ethernet networks.n");
                /* �ͷ��豸�б� */
                pcap_freealldevs(alldevs);
                return -1;
        }

        if(d->addresses != NULL)
        /* ��ýӿڵ�һ����ַ������ */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        else
        /* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
        netmask=0xffffff;


        //���������
        if (pcap_compile(adhandle, &fcode, NULL, 1, netmask) <0 ) //�����������ݰ�
        {
                fprintf(stderr,"nUnable to compile the packet filter. Check the syntax.n");
                /* �ͷ��豸�б� */
                pcap_freealldevs(alldevs);
                return -1;
        }

        //���ù�����
        if (pcap_setfilter(adhandle, &fcode)<0)
        {
                fprintf(stderr,"nError setting the filter.n");
                /* �ͷ��豸�б� */
                pcap_freealldevs(alldevs);
                return -1;
        }

        printf("nlistening on %s...n", d->description);

        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);

        /* ��ʼ��׽ */

        pcap_loop(adhandle, 0, packet_handler, NULL);

        return 0;
}
/****************************************************************/

/***********************��ʼ�����û�̬���ݰ�*********************/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
        unsigned char *pBuffer;
        pBuffer = (unsigned char *)pkt_data;

        PACKET_READ *packet_read_user;
        packet_read_user = new PACKET_READ;
        PACKET_SAVE *pre_save, *save = new PACKET_SAVE;

        packet_read_user = frame(pBuffer, packet_read_user);
        if(packet_read_user != 0)
        {
                save->packet_read = packet_read_user;
                save->count = packet_user_save_count;
                save->next = NULL;
                if(packet_user_save_count == 0)
                {
                        packet_user_root->next = save;
                        packet_user_save_count ++;
                }
                else
                {
                        pre_save = packet_user_root;
                        while(pre_save->next != NULL)
                        {
                                if(pre_save->next->packet_read->IP_DST_ADDR == packet_read_user->IP_DST_ADDR
                                        && pre_save->next->packet_read->IP_SRC_ADDR == packet_read_user->IP_SRC_ADDR
                                        && pre_save->next->packet_read->DST_PORT == packet_read_user->DST_PORT
                                        && pre_save->next->packet_read->SRC_PORT == packet_read_user->SRC_PORT)
                                {
                                        pre_save->next->packet_read->ACK = packet_read_user->ACK;
                                        pre_save->next->packet_read->SEQ = packet_read_user->SEQ;
                                        pre_save->next->packet_read->TCP_DATA_LEN = packet_read_user->TCP_DATA_LEN;
                                        break;
                                }
                                pre_save = pre_save->next;
                        }
                        if(pre_save->next == NULL)
                        {
                                pre_save->next = save;
                                packet_user_save_count ++;
                        }
                }
        }
}
/****************************************************************/

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
 //                     cout<<endl;
                        break;
                }
        }
        else																			//����õ�IP��
        {
                IHL = longip->iphead->VAI & 15;
                switch(longip->iphead->protocol)
                {
                case 1:
                        break;
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
        int first, last;
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

/****************************��ȡ�ں�̬���ݰ�����****************************/
/*
PACKET_SAVE *get_packet_root()
{
        return packet_root;
}
*/
/*************************************************************************/

/****************************��ȡ�û�̬��������******************************/
PACKET_SAVE *get_user_packet_root()
{
        return packet_user_root;
}
/*************************************************************************/

/***************************��ȡ�û�̬���Ӹ���*******************************/
unsigned int get_packet_user_save_count()
{
    return packet_user_save_count;
}
/*************************************************************************/

/*
void create_packet()
{
        tcp_create(packet_root);
}
*/
