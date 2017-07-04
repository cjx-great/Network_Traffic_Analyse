#include <time.h>

//以太网报头
typedef struct ethernet_header{

    unsigned char host_dest[6];      //目的地址 48位
    unsigned char host_src[6];       //源地址  48位
    unsigned short type;             //类型   16位

    #define ETHER_TYPE_MIN      0x0600          //XEROX NS IDP协议
    #define ETHER_TYPE_IP       0x0800          //IP协议
    #define ETHER_TYPE_ARP      0x0806          //地址解析协议ARP
    #define ETHER_TYPE_8021Q    0x8100          //以太网自动保护开关EAPS
    #define ETHER_TYPE_BRCM     0x886c          //
    #define ETHER_TYPE_802_1X   0x888e          //
    #define ETHER_TYPE_802_1X_PREAUTH   0x88c7  //

}ETHERNET_HEADER;

//4字节的IP地址
typedef struct ip_address{
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
}ip_address;

//IP报头
typedef struct ip_header{

    unsigned char version_headLength;           //4位版本号+4位首部长度
    unsigned char tos;                          //服务类型  8位
    unsigned short total_length;                //总长度   16位
    unsigned short identification;              //标识    16位
    unsigned short flag_offset;                 //3位标志+13位片偏移
    unsigned char ttl;                          //生存时间  8位
    unsigned char protocol;                     //协议 8位
    #define IP_ICMP     1
    #define IP_IGMP     2
    #define IP_TCP      6
    #define IP_UDP      17
    #define IP_IGRP     88
    #define IP_OSPF     89

    unsigned short crc;                         //首部校验和   16位
    ip_address src_ip_address;                  //源IP地址     32位
    ip_address dest_ip_address;                 //目的IP地址    32位
    unsigned int option_padding;                // 选项与填充 32位

}IP_HEADER;

//TCP报头
typedef struct tcp_header{

    unsigned short src_port;                    //源端口号  16位
    unsigned short dest_port;                   //目的端口号 16位
    unsigned int sequence;                      //序号  32位
    unsigned int ack;                           //确认序号  32位
    //首部长度4位 + 保留位6位 + 标记6位
    unsigned short headlen_retain_flag;

    #define TH_FIN	0x0001
    #define TH_SYN	0x0002
    #define TH_RST	0x0004
    #define TH_PSH	0x0008
    #define TH_ACK	0x0010
    #define TH_URG	0x0020

    unsigned short win_size;                    //窗口大小  16位
    unsigned short check_sum;                   //校验和   16位
    unsigned short urgent;                      //紧急指针   16位

}TCP_HEADER;

//UDP报头
typedef struct udp_header{

    unsigned short src_port;                    //源端口号  16位
    unsigned short dest_port;                   //目的端口号 16位
    unsigned short length;                      //UDP长度     16位
    unsigned short check_sum;                   //UDP校验和   16位

}UDP_HEADER;

//hash表结点
typedef struct hash_node{

    //便于比较
    char src_ip_addr[50];                       //源IP
    char dest_ip_addr[50];                      //目的IP
    unsigned short src_port;                    //源端口号
    unsigned short dest_port;                   //目的端口号
    time_t catch_time;                          //数据包捕获时间
    unsigned int packet_len;                    //数据包长度(包含首部)
    struct Node *next;

}HASH_NODE;

//hash表
typedef struct hash_table{

    HASH_NODE *table_head;
    unsigned int node_count;

}HASH_TABLE;
