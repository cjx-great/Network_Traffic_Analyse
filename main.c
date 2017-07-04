#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include "header.h"

#define FILE_NAME "packet.txt"
//协议个数
#define PROTOCOL_COUNT 2
//协议名称
char protocols[PROTOCOL_COUNT][7] = {"TCP", "UDP"};
HASH_TABLE hashTable[PROTOCOL_COUNT];

typedef struct _argument{
    pcap_t *handle;
    int timeLen;
}argument;

//子线程运行函数
void *thread_clock(void *argv);
//包捕获处理函数
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data);
//统计模式下的包处理函数
void countMode_packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data);
//数据报解析函数
void parse(const u_char *packet_data, time_t catch_time, int packet_size);
//相关输出文件的创建函数
int creatFile();
//根据协议数量初始化hashtable
void initHashTable();
//根据协议名获取其链表位置
int getProtocolLinkIndex(char *pro_name);
//将数据包插入hashtable
void insertIntoHash(HASH_TABLE *link, HASH_NODE *node);
//流量分析
void analyseFlow(char *pro_name);

int main(){
    /* 初始化操作 */
    //创建输出文件
    if(creatFile() == -1){
        return -1;
    }

    //初始化hash表
    initHashTable();

    pcap_if_t *alldevs;
    //错误信息缓存区
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device;

    /* 获取网卡设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, error_buffer) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", error_buffer);
        exit(1);
    }

    /* 打印列表 */
    printf("网络适配器列表:\n");
    pcap_if_t *dev;
    int i = 0;
    for(dev = alldevs; dev ; dev = dev->next){
        printf("%d.\t%s\n", ++i, dev->name);
        if (dev->description){
            printf("\t(%s)\n\n", dev->description);
        }else{
            printf("\t(No description available)\n\n");
        }
    }

    if(i == 0){
        printf("\n错误：未发现设备!!!\n");
        return -1;
    }

    int num;
    printf("选择设备号（1-%d）:",i);
    scanf("%d",&num);
    getchar();
    if(num < 1 || num > i){
        printf("输入范围错误\n");
        //释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 跳转到选中的适配器 */
    for(dev = alldevs, i=0; i < num-1 ;dev = dev->next, i++);
    /* 打开设备 */
    pcap_t *devHandler;
    if ((devHandler = pcap_open(dev->name,
                                65536,    // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                PCAP_OPENFLAG_PROMISCUOUS,      //网卡进入混杂模式
                                1000,   // 读取超时时间(意味着统计模式下每隔一秒回调一次处理函数)
                                NULL,
                                error_buffer)) == NULL){
        fprintf(stderr,"\n适配器打开失败,不支持%s\n", dev->name);
        //释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 检查数据链路层，只考虑以太网 */
    if(pcap_datalink(devHandler) != DLT_EN10MB){
        fprintf(stderr,"\n该程序只分析以太网数据帧,该设备不支持,请重选设备\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //网络号与掩码
    bpf_u_int32 net, mask;
    //获得网卡的网络号与掩码
    pcap_lookupnet(dev, &net, &mask, error_buffer);

    struct bpf_program fcode;
    //char packet_filter[] = "ip or tcp or udp";  //ether要MAC地址
    char packet_filter[50];
    printf("输入过滤规则:");
    gets(packet_filter);
    /* 编译过滤规则 */
    //将第三个参数指定的字符串编译到过滤程序中
    //第四个参数控制结果代码的优化
    //最后一个参数指定本地网络的网络掩码
    //这一步给fcode赋值
    if (pcap_compile(devHandler, &fcode, packet_filter, 1, mask) < 0){
        printf("\n过滤规则编译失败\n");
        return -1;
    }
    /* 设置过滤规则 */
    if (pcap_setfilter(devHandler, &fcode) < 0){
        printf("\n过滤规则设置失败\n");
        return -1;
    }

    /* 开启子线程 */
    pthread_t clock_thread;
    argument arg;
    int argv_time;

    printf("输入抓取时间(秒):");
    scanf("%d", &argv_time);
    arg.timeLen = (argv_time > 0) ? argv_time : 60;
    arg.handle = devHandler;
    printf("抓取时长：%d s\n", arg.timeLen);
    //argument结构体传入
    if(pthread_create(&clock_thread, NULL, thread_clock, &arg)){
        printf("线程创建失败\n");
        return -1;
    }

    printf("\n正在监听:%s...\n", dev->description);

    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    /* 开始捕获 */
    //第二个是指定捕获的数据包个数,如果为-1则无限循环捕获
    //抓到数据包后执行packet_handler回调函数
    printf("id\ttime\t\tlength\tdata\n");
    pcap_loop(devHandler, -1, packet_handler, NULL);

    /* 关闭处理 */
    pcap_close(devHandler);
    printf("\n\t\t---抓取结束---\n\n");

    /* 根据输入协议名查看流量 */
    char pro_name[10];
    printf("目前支持的协议:");
    int j;
    for(j = 0;j < PROTOCOL_COUNT;j++){
        printf("%s\t", protocols[j]);
    }
    printf("\n");
    getchar();
    while(1){
        pro_name[0] = '\0';
        printf("输入协议名查看其流量分析情况(end结束):");
        gets(pro_name);
        if(strcmp(pro_name, "end") == 0){
            break;
        }

        if(getProtocolLinkIndex(pro_name) == -1){
            printf("输入错误!!!\n\n");
            continue;
        }

        analyseFlow(pro_name);
    }

    printf("\n运行结束\n\n");

    return 0;
}

/* 子线程运行函数 */
void *thread_clock(void *argv){
    //使自身变成非阻塞线程
    pthread_detach(pthread_self());

    pcap_t *handle = ((argument*)argv)->handle;
    int timeLen = ((argument*)argv)->timeLen;
    //单位是毫秒
    Sleep(timeLen*1000);
    //停止抓包
    pcap_breakloop(handle);
}

/* 包捕获处理函数
   最后一个参数指向一块内存空间，这个空间中存放的就是pcap_loop抓到的数据包
   第二个参数结构体是由pcap_loop自己填充的，用来取得一些关于数据包的信息 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data){
    struct tm *_tm;
    char time[16];
    time_t local_tv_sec;
    static int id = 0;

    //将时间戳转换成可识别的格式
    local_tv_sec = header->ts.tv_sec;
    _tm = localtime(&local_tv_sec);
    strftime(time, sizeof(time), "%H:%M:%S", _tm);

    /* 屏幕输出 */
    //len表示数据包的实际长度
    printf("-------------------------------------------\n\n");
    printf("%d\t%s\t%d\t", ++id, time, header->len);
    int i = 0;
    for(i = 0;i < header->len;i++){
        if(isprint(packet_data[i])){
            printf("%c", packet_data[i]);
        }else{
            printf(". ");
        }
        if((i%16 == 0 && i != 0) || i == header->len-1){
            printf("\n\t\t\t\t");
        }
    }
    printf("\n");

    ETHERNET_HEADER *ether;
    ether = (ETHERNET_HEADER *)(packet_data);
    printf("\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           ether->host_src[0],
           ether->host_src[1],
           ether->host_src[2],
           ether->host_src[3],
           ether->host_src[4],
           ether->host_src[5],
           ether->host_dest[0],
           ether->host_dest[1],
           ether->host_dest[2],
           ether->host_dest[3],
           ether->host_dest[4],
           ether->host_dest[5]);

    /* 数据包解析 */
    parse(packet_data, header->ts.tv_sec, header->len);

}

/* 创建“五元组”文件 */
int creatFile(){
    remove(FILE_NAME);
    FILE *f;
    f = fopen(FILE_NAME, "w+");
    if(f == NULL){
        printf("\n输出文件创建失败!!\n");
        return -1;
    }
    fprintf(f, "序号\t");
    fprintf(f, "确认序号\t");
    fprintf(f, "标记位\t\t\t");
    fprintf(f, "源IP\t\t\t");
    fprintf(f, "目的IP\t\t\t");
    fprintf(f, "源端口\t\t");
    fprintf(f, "目的端口\t");
    fprintf(f, "协议\t");
    fprintf(f, "数据大小\n");

    fclose(f);

    return 0;
}

/* 解析数据包 */
void parse(const u_char *packet_data, time_t catch_time, int packet_size){
    /* 获得IP数据包头部 */
    IP_HEADER *ip;
    unsigned int protocol;
    unsigned int ip_head_len;
    unsigned int ip_total_len;

    //以太网头部占14字节
    ip = (IP_HEADER *)(packet_data + 14);
    //数据包协议
    protocol = *((unsigned int *)(&ip->protocol)) & 0xff;
    //IP头部长度
    ip_head_len = (ip->version_headLength & 0xf)*4;
    //IP总长度
    ip_total_len = ntohs(ip->total_length);
    //数据包长度
    unsigned int packet_len = ip_total_len - ip_head_len;
    //源IP
    char src_ip[50];
    sprintf(src_ip, "%d.%d.%d.%d",
            ip->src_ip_address.byte1,
            ip->src_ip_address.byte2,
            ip->src_ip_address.byte3,
            ip->src_ip_address.byte4);
    //目的IP
    char dest_ip[50];
    sprintf(dest_ip, "%d.%d.%d.%d",
            ip->dest_ip_address.byte1,
            ip->dest_ip_address.byte2,
            ip->dest_ip_address.byte3,
            ip->dest_ip_address.byte4);

    unsigned short src_port, dest_port;
    unsigned int ack;
    unsigned int sequence;
    unsigned short flag;
    //数据长度
    unsigned int data_len;
    char flag_str[100];
    char pro_name[5];

    //新建hash结点
    HASH_NODE *node = (HASH_NODE*)malloc(sizeof(HASH_NODE));
    node->next = NULL;
    node->catch_time = catch_time;
    node->packet_len = packet_size;
    strcpy(node->src_ip_addr, src_ip);
    strcpy(node->dest_ip_addr, dest_ip);

    int index;
    if(protocol == IP_TCP){             //TCP协议报头
        /* 获得TCP首部 */
        TCP_HEADER *tcp;
        tcp = (TCP_HEADER *)((unsigned char *)ip + ip_head_len);

        //从网络字节顺序(大端)转换为主机字节顺序（小端）
        //大端模式：最高位放低地址
        //小端模式：最低位放低地址
        src_port = ntohs(tcp->src_port);
        dest_port = ntohs(tcp->dest_port);
        ack = ntohs(tcp->ack);
        sequence = ntohs(tcp->sequence);
        //TCP首部长度
        unsigned short hrf = ntohs(tcp->headlen_retain_flag);
        unsigned int tcp_head_len = ((hrf & 0xf000) >> 12)*4;
        //TCP数据长度
        data_len = packet_len - tcp_head_len;
        //标记
        flag = hrf & 0x3f;

        strcpy(flag_str, "");
        if((flag & TH_ACK) == TH_ACK){
            strcat(flag_str, "ACK=1 ");
        }else{
            strcat(flag_str, "ACK=0 ");
        }

        if((flag & TH_SYN) == TH_SYN){
            strcat(flag_str, "SYN=1 ");
        }else{
            strcat(flag_str, "SYN=0 ");
        }

        if((flag & TH_FIN) == TH_FIN){
            strcat(flag_str, "FIN=1");
        }else{
            strcat(flag_str, "FIN=0");
        }

        strcpy(pro_name, "TCP");

    }else if(protocol == IP_UDP){                //UDP协议报头
        /* 获得UDP首部 */
        UDP_HEADER *udp;
        udp = (UDP_HEADER *)((unsigned char *)ip + ip_head_len);

        //从网络字节顺序转换为主机字节顺序
        unsigned short tcp_head_len;
        src_port = ntohs(udp->src_port);
        dest_port = ntohs(udp->dest_port);
        tcp_head_len = ntohs(udp->length);
        data_len = packet_len - tcp_head_len;

        strcpy(flag_str, "\t\t");
        ack = -1;
        sequence = -1;
        strcpy(pro_name, "UDP");

    }else{
        // TODO 其它协议
        strcpy(flag_str, "\t\t");
    }

    //插入hash结点
    node->src_port = src_port;
    node->dest_port = dest_port;
    index = getProtocolLinkIndex(pro_name);
    HASH_TABLE *table = &hashTable[index];
    insertIntoHash(table, node);


    FILE *f;
    f = fopen(FILE_NAME, "a+");
    if(f == NULL){
        printf("\n该数据包写入文件失败\n");
        return;
    }

    char buffer[50];
    //序号
    sprintf(buffer, "%d\t", sequence);
    fprintf(f, buffer);
    //确认序号
    sprintf(buffer, "%d\t\t", ack);
    fprintf(f, buffer);
    //标记位
    sprintf(buffer, "%s\t", flag_str);
    fprintf(f, buffer);
    //源IP
    fprintf(f, src_ip);
    fprintf(f, "\t\t");
    //目的IP
    fprintf(f, dest_ip);
    fprintf(f, "\t\t");
    //源端口
    sprintf(buffer, "%d\t\t",src_port);
    fprintf(f, buffer);
    //目的端口
    sprintf(buffer, "%d\t\t",dest_port);
    fprintf(f, buffer);
    //协议
    fprintf(f, pro_name);
    fprintf(f, "\t");
    //数据包大小
    sprintf(buffer, "%d", data_len);
    fprintf(f, buffer);
    fprintf(f, "\n");

    fclose(f);

    printf("%s\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n\n",pro_name,
            ip->src_ip_address.byte1,
            ip->src_ip_address.byte2,
            ip->src_ip_address.byte3,
            ip->src_ip_address.byte4,src_port,
            ip->dest_ip_address.byte1,
            ip->dest_ip_address.byte2,
            ip->dest_ip_address.byte3,
            ip->dest_ip_address.byte4,dest_port);

}

/* 初始化hashtable */
void initHashTable(){
    int i;
    for(i = 0;i < PROTOCOL_COUNT;i++){
        hashTable[i].table_head = NULL;
        hashTable[i].node_count = 0;
    }
}

/* 根据协议名获取其链表位置 */
int getProtocolLinkIndex(char *pro_name){
    int i = 0;
    for(;i < PROTOCOL_COUNT;i++){
        if(strcmp(pro_name, protocols[i]) == 0){
            return i;
        }
    }

    return -1;
}

/* 将数据包插入hashtable */
void insertIntoHash(HASH_TABLE *link, HASH_NODE *node){
    link->node_count++;
    HASH_NODE *head_node = link->table_head;
    if(head_node == NULL){
        link->table_head = node;
        return;
    }

    for(;head_node->next != NULL;head_node = head_node->next);
    head_node->next = node;

    return;
}

/* 流量分析 */
void analyseFlow(char *pro_name){
    int index = getProtocolLinkIndex(pro_name);
    HASH_TABLE *table = &hashTable[index];
    HASH_NODE *node = table->table_head;

    if(node == NULL){
        printf("\n\t---尚未抓取到该协议数据包---\n\n");
        return;
    }

    int count = table->node_count;
    int i;
    for(i =0;i < count;i++){
        printf("%d\tsrc_port:%d\tsrc_ip:%s\n",i+1,
                node->src_port,
                node->src_ip_addr);
        node = node->next;
    }
}
