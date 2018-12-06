#include "my_packet.h"
#include <iostream>
using namespace std;

PACKET_SAVE *packet_root;		//存放内核态连接数据信息链表
unsigned int packet_save_count = 0;				//计数器，记录内核态连接个数

PACKET_SAVE *packet_user_root;		//存放内核态连接数据信息链表
unsigned int packet_user_save_count = 0;				//计数器，记录内核态连接个数

re_head *root;					//存放重组ip的链表
int root_flag = 1;								//标志，1表示没有根结点为空

void init()
{
    packet_root = new PACKET_SAVE;		//存放内核态连接数据信息链表
    memset(packet_root, 0, sizeof(PACKET_SAVE));
    packet_save_count = 0;				//计数器，记录内核态连接个数

    packet_user_root = new PACKET_SAVE;		//存放用户态连接数据信息链表
    memset(packet_user_root, 0, sizeof(PACKET_SAVE));
    packet_user_save_count = 0;				//计数器，记录用户态连接个数

    root = new re_head;					//存放重组ip的链表
    memset(root, 0, sizeof(re_head));
    root_flag = 1;
}

/**************************用户态抓包****************************/
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
        /*设置监听类型*/
        //SetIpsort(packet_filter,4);

        /* 获得设备列表 */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
        }

        /* 输出列表 */
        for(d=alldevs;d;d=d->next)
        {
                printf("%d. %s", ++i, d->name);
                if (d->description)
                printf(" (%s)\n", d->description);
                else
                /* Y- 没有有效的描述 */
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
//                /* 释放设备列表 */
//                pcap_freealldevs(alldevs);
//                return -1;
//        }

        inum = 1;
        /* 跳转到已选设备 */
        for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

        printf("%s",inet_ntoa(((struct sockaddr_in*)(d->addresses->addr))->sin_addr));
        /* 打开适配器 */
        if ((adhandle= pcap_open_live(d->name, //设备名
                65536, // 捕捉完整的数据包
                0, // 混在模式 //混合模式 1 打开混合模式 0关闭混合模式
                1000, // 读入超时
                errbuf // 错误缓冲
                )) == NULL)
        {
                /* Y- 打开失败*/
                fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
                /* 释放列表 */
                pcap_freealldevs(alldevs);
                return -1;
        }

        /* 检查数据链路层，为了简单，我们只考虑以太网 */
        if(pcap_datalink(adhandle) != DLT_EN10MB)
        {
                fprintf(stderr,"nThis program works only on Ethernet networks.n");
                /* 释放设备列表 */
                pcap_freealldevs(alldevs);
                return -1;
        }

        if(d->addresses != NULL)
        /* 获得接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;


        //编译过滤器
        if (pcap_compile(adhandle, &fcode, NULL, 1, netmask) <0 ) //接受所有数据包
        {
                fprintf(stderr,"nUnable to compile the packet filter. Check the syntax.n");
                /* 释放设备列表 */
                pcap_freealldevs(alldevs);
                return -1;
        }

        //设置过滤器
        if (pcap_setfilter(adhandle, &fcode)<0)
        {
                fprintf(stderr,"nError setting the filter.n");
                /* 释放设备列表 */
                pcap_freealldevs(alldevs);
                return -1;
        }

        printf("nlistening on %s...n", d->description);

        /* 释放设备列表 */
        pcap_freealldevs(alldevs);

        /* 开始捕捉 */

        pcap_loop(adhandle, 0, packet_handler, NULL);

        return 0;
}
/****************************************************************/

/***********************开始处理用户态数据包*********************/
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

/***********************处理嗅探到的数据*************************/
void sniff(unsigned char *pBuffer)
{
        PACKET_READ *packet_read_temp = new PACKET_READ;					//存放每一个数据包需要的数据
        PACKET_SAVE *pre_save, *save = new PACKET_SAVE;

        packet_read_temp = frame(pBuffer, packet_read_temp);					//开始处理读入的每一个数据包，将需要的数据存放在packet_temp中

        if(packet_read_temp != 0)												//将处理后的结果进行进一步处理
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
                                if(pre_save->next->packet_read->IP_DST_ADDR == packet_read_temp->IP_DST_ADDR		//对已有链接进行更新
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
                        if(pre_save->next == NULL)												//将新的链接入队列
                        {
                                pre_save->next = save;
                                packet_save_count ++;
                        }
                }
        }
}
/*************************************************************************/

/**************************对以太网帧首部进行处理*************************/
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
                return 0;																	//如果不是IPv4包，返回0
        else																			//如果是IPv4包，开始处理
                return ip_solve(pBuffer + 14, packet_read_temp);
}
/*************************************************************************/

/*****************************处理IP首部**********************************/
PACKET_READ *ip_solve(unsigned char *pBuffer, PACKET_READ *packet_read_temp)
{
        IP_HEAD *ip_head;
        re_head *longip;																//需要重组的IPv4包
        longip = 0;
        unsigned char *temp;
        unsigned char IHL, flag, MF;
        unsigned short offset;
        unsigned short length;															//IP包总长度
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
        if(MF == 1 || offset != 0)														//需要重组
        {
                longip = ip_recombine(pBuffer, length);
                if(longip == 0)																//未重组完
                        return 0;
        }
        if(!longip)																		//不需要重组
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
        else																			//重组好的IP包
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

/************************对分片的IP包进行重组*****************************/
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

/******************************处理TCP首部*******************************/
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

/******************************处理UDP首部********************************/
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

/*******************************打印连接信息******************************/
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

/****************************打印MAC地址**********************************/
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

/******************************打印IP地址*********************************/
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

/****************************获取内核态数据包链表****************************/
/*
PACKET_SAVE *get_packet_root()
{
        return packet_root;
}
*/
/*************************************************************************/

/****************************获取用户态数据链表******************************/
PACKET_SAVE *get_user_packet_root()
{
        return packet_user_root;
}
/*************************************************************************/

/***************************获取用户态链接个数*******************************/
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
