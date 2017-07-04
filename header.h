#include <time.h>

//��̫����ͷ
typedef struct ethernet_header{

    unsigned char host_dest[6];      //Ŀ�ĵ�ַ 48λ
    unsigned char host_src[6];       //Դ��ַ  48λ
    unsigned short type;             //����   16λ

    #define ETHER_TYPE_MIN      0x0600          //XEROX NS IDPЭ��
    #define ETHER_TYPE_IP       0x0800          //IPЭ��
    #define ETHER_TYPE_ARP      0x0806          //��ַ����Э��ARP
    #define ETHER_TYPE_8021Q    0x8100          //��̫���Զ���������EAPS
    #define ETHER_TYPE_BRCM     0x886c          //
    #define ETHER_TYPE_802_1X   0x888e          //
    #define ETHER_TYPE_802_1X_PREAUTH   0x88c7  //

}ETHERNET_HEADER;

//4�ֽڵ�IP��ַ
typedef struct ip_address{
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
}ip_address;

//IP��ͷ
typedef struct ip_header{

    unsigned char version_headLength;           //4λ�汾��+4λ�ײ�����
    unsigned char tos;                          //��������  8λ
    unsigned short total_length;                //�ܳ���   16λ
    unsigned short identification;              //��ʶ    16λ
    unsigned short flag_offset;                 //3λ��־+13λƬƫ��
    unsigned char ttl;                          //����ʱ��  8λ
    unsigned char protocol;                     //Э�� 8λ
    #define IP_ICMP     1
    #define IP_IGMP     2
    #define IP_TCP      6
    #define IP_UDP      17
    #define IP_IGRP     88
    #define IP_OSPF     89

    unsigned short crc;                         //�ײ�У���   16λ
    ip_address src_ip_address;                  //ԴIP��ַ     32λ
    ip_address dest_ip_address;                 //Ŀ��IP��ַ    32λ
    unsigned int option_padding;                // ѡ������� 32λ

}IP_HEADER;

//TCP��ͷ
typedef struct tcp_header{

    unsigned short src_port;                    //Դ�˿ں�  16λ
    unsigned short dest_port;                   //Ŀ�Ķ˿ں� 16λ
    unsigned int sequence;                      //���  32λ
    unsigned int ack;                           //ȷ�����  32λ
    //�ײ�����4λ + ����λ6λ + ���6λ
    unsigned short headlen_retain_flag;

    #define TH_FIN	0x0001
    #define TH_SYN	0x0002
    #define TH_RST	0x0004
    #define TH_PSH	0x0008
    #define TH_ACK	0x0010
    #define TH_URG	0x0020

    unsigned short win_size;                    //���ڴ�С  16λ
    unsigned short check_sum;                   //У���   16λ
    unsigned short urgent;                      //����ָ��   16λ

}TCP_HEADER;

//UDP��ͷ
typedef struct udp_header{

    unsigned short src_port;                    //Դ�˿ں�  16λ
    unsigned short dest_port;                   //Ŀ�Ķ˿ں� 16λ
    unsigned short length;                      //UDP����     16λ
    unsigned short check_sum;                   //UDPУ���   16λ

}UDP_HEADER;

//hash����
typedef struct hash_node{

    //���ڱȽ�
    char src_ip_addr[50];                       //ԴIP
    char dest_ip_addr[50];                      //Ŀ��IP
    unsigned short src_port;                    //Դ�˿ں�
    unsigned short dest_port;                   //Ŀ�Ķ˿ں�
    time_t catch_time;                          //���ݰ�����ʱ��
    unsigned int packet_len;                    //���ݰ�����(�����ײ�)
    struct Node *next;

}HASH_NODE;

//hash��
typedef struct hash_table{

    HASH_NODE *table_head;
    unsigned int node_count;

}HASH_TABLE;
