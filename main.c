#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include "header.h"
#include <sys/stat.h>
#include <unistd.h>

#define FILE_NAME "packet.txt"
//协议个数
#define PROTOCOL_COUNT 2
//协议名称
char protocols[PROTOCOL_COUNT][7] = {"TCP", "UDP"};
HASH_TABLE hashTable[PROTOCOL_COUNT];
//抓取到的第一个包的时间
time_t first_catch_time;
//抓取到的最后一个包的时间
time_t last_catch_time;
//本机IP
char *local_ip;

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
void parse(const u_char *packet_data, char *catch_time, int packet_size);
//相关输出文件的创建函数
int creatFile();
//根据协议数量初始化hashtable
void initHashTable();
//释放hashtable占的内存
void freeHashTable();
//填充hashtable
int fillHashTable(time_t start_time, time_t end_time);
//打印流量分析结果
void printFlowAnalyseRes(time_t start_time, time_t end_time);
//根据协议名获取其链表位置
int getProtocolLinkIndex(char *pro_name);
//将数据包插入hashtable
void insertIntoHash(HASH_TABLE *link, HASH_NODE *node);
//流量分析
void analyseFlow(int time_pad);
//字符串分割函数
void split(char **arr, char *str, const char *del);

int main(){
    /* 初始化操作 */
    //创建输出文件
    if(creatFile() == -1){
        return -1;
    }

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
    /* 获得本地IP */
    struct pcap_addr *addr = dev->addresses;
    struct sockaddr_in *sin;
    for(;addr;addr = addr->next){
        sin = (struct sockaddr_in *)addr->addr;
        if(sin->sin_family = AF_INET){
            local_ip = inet_ntoa(sin->sin_addr);
        }
    }
    /* 打开设备 */
    pcap_t *devHandler;
    if ((devHandler = pcap_open(dev->name,
                                65536,    // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                PCAP_OPENFLAG_PROMISCUOUS,      //网卡进入混杂模式
                                1000,   // 读取超时时间
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
    printf("id\ttime\t\t\tlength\tdata\n");
    pcap_loop(devHandler, -1, packet_handler, NULL);

    /* 关闭处理 */
    pcap_close(devHandler);
    printf("\n\t\t---抓取结束---\n\n");

    /* 根据输入协议名查看流量 */
    printf("目前支持的协议:");
    int j;
    for(j = 0;j < PROTOCOL_COUNT;j++){
        printf("%s\t", protocols[j]);
    }
    printf("\n");
    getchar();

    //初始化hash表
    initHashTable();

    int time_pad;
    printf("\n\t\t-----查看流量分析情况----\n\n");
    while(1){
        printf("输入时间间隔(秒)('-1'结束):");
        scanf("%d", &time_pad);
        getchar();

        if(time_pad == -1){
            break;
        }
        //检查输入是否合法
        if(time_pad > arg.timeLen){
            printf("输入错误!!!时间间隔不能大于抓取时间%ds\n\n", arg.timeLen);
            continue;
        }

        analyseFlow(time_pad);
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
    struct tm _tm;
    char time[20];
    time_t local_tv_sec;
    static int id = 0;

    //将时间戳转换成可识别的格式
    local_tv_sec = header->ts.tv_sec;
    _tm = *localtime(&local_tv_sec);
    sprintf(time, "%4.4d.%2.2d.%2.2d-%2.2d:%2.2d:%2.2d",
        _tm.tm_year+1900, _tm.tm_mon + 1, _tm.tm_mday,
        _tm.tm_hour, _tm.tm_min, _tm.tm_sec );

    //strftime(time, sizeof(time), "%H:%M:%S", _tm);

    //记录抓包时间
    if(id == 0){
        first_catch_time = local_tv_sec;
    }
    last_catch_time = local_tv_sec;

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
            printf("\n\t\t\t\t\t");
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
    parse(packet_data, time, header->len);

}

int creatFile(){
    /* 创建“五元组”文件 */
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

    /* 创建流量分析输出文件 */
    char fileName[10];
    int i = 0;
    for(;i < PROTOCOL_COUNT;i++){
        sprintf(fileName, "%s.txt", protocols[i]);
        remove(fileName);
        FILE *flow = fopen(fileName, "w+");
        if(flow == NULL){
            fprintf("%s协议流量分析文件创建失败!!\n", protocols[i]);
            return -1;
        }
        fclose(flow);
    }

    return 0;
}

/* 解析数据包 */
void parse(const u_char *packet_data, char *catch_time, int packet_size){
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

    /* 固定格式写入流量分析统计文件 */
    /* 抓取时间@源IP@目的IP@源端口@目的端口@数据包长度 */
    char file_node[100];
    strcpy(file_node, catch_time);
    strcat(file_node, "@");
    strcat(file_node, src_ip);
    strcat(file_node, "@");
    strcat(file_node, dest_ip);
    strcat(file_node, "@");

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

    char buf[10];
    itoa(src_port, buf, 10);
    strcat(file_node, buf);
    strcat(file_node, "@");
    itoa(dest_port, buf, 10);
    strcat(file_node, buf);
    strcat(file_node, "@");
    itoa(packet_len, buf, 10);
    strcat(file_node, buf);
    strcat(file_node, "\n");

    char flowName[10];
    sprintf(flowName, "%s.txt", pro_name);
    FILE *flow = fopen(flowName, "a+");
    if(flow == NULL){
        printf("\n该数据包写入流量分析文件失败\n\n");
    }else{
        fprintf(flow, file_node);
    }
    fclose(flow);

    /* 固定格式写入数据包记录文件 */
    FILE *f;
    f = fopen(FILE_NAME, "a+");
    if(f == NULL){
        printf("\n该数据包写入文件失败\n");
    }else{
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
    }
    fclose(f);

    //打印IP
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

/* 释放前一次hashtable占的内存 */
void freeHashTable(){
    int i = 0;
    for(;i < PROTOCOL_COUNT;i++){
        int index = getProtocolLinkIndex(protocols[i]);
        HASH_TABLE *table = &hashTable[index];
        HASH_NODE *node = table->table_head;

        if(node != NULL){
            int j = 0;
            HASH_NODE *next_node;
            for(;j < table->node_count-1;j++){
                next_node = node->next;
                free(node);
                node = next_node;
            }
            free(next_node);
        }

        table->node_count = 0;
        table->table_head = NULL;
    }
}

/* 填充hashtable */
int fillHashTable(time_t start_time, time_t end_time){
    freeHashTable();

    /* 抓取时间@源IP@目的IP@源端口@目的端口@数据包长度 */
    int i = 0;
    char file_name[7];
    for(;i < PROTOCOL_COUNT;i++){
        sprintf(file_name, "%s.txt", protocols[i]);
        //先判断文件中是否有数据
        struct stat st ;
        stat(file_name, &st);
        if(st.st_size > 0){
            FILE *file = fopen(file_name, "r");
            if(file == NULL){
                return -1;
            }

            char file_node[100];
            while(!feof(file)){
                fgets(file_node, 100, file);
                strtok(file_node, "\n");
                //字符串分割
                char delims[] = "@";
                char *myArray[6];
                memset(myArray, 0x0, sizeof(myArray));
                split(myArray, file_node, delims);

                if(myArray[1] != NULL){
                    //时间判断
                    char *c = myArray[0];
                    struct tm tm_tmp;
                    time_t catch_time;
                    sscanf( c, "%4d.%2d.%2d-%2d:%2d:%2d",
                            &tm_tmp.tm_year,
                            &tm_tmp.tm_mon,
                            &tm_tmp.tm_mday,
                            &tm_tmp.tm_hour,
                            &tm_tmp.tm_min,
                            &tm_tmp.tm_sec );

                            tm_tmp.tm_year -= 1900;
                            tm_tmp.tm_mon --;
                            tm_tmp.tm_isdst=-1;

                    catch_time = mktime( &tm_tmp );
                    //链表插入
                    if((catch_time >= start_time)&&(catch_time <= end_time)){
                        /* 抓取时间@源IP@目的IP@源端口@目的端口@数据包长度 */
                        HASH_NODE *node = (HASH_NODE*)malloc(sizeof(HASH_NODE));
                        node->catch_time = catch_time;
                        strcpy(node->src_ip_addr, myArray[1]);
                        strcpy(node->dest_ip_addr, myArray[2]);
                        node->src_port = atoi(myArray[3]);
                        node->dest_port = atoi(myArray[4]);
                        node->packet_len = atoi(myArray[5]);
                        node->next = NULL;

                        int index = getProtocolLinkIndex(protocols[i]);
                        HASH_TABLE *table = &hashTable[index];
                        insertIntoHash(table, node);
                    }

                }
            }

            fclose(file);

        }
    }

    return 0;
}

void split(char **arr, char *str, const char *del){
    char *s = NULL;
    s = strtok(str, del);
    while(s != NULL){
        *arr++ = s;
        s = strtok(NULL, del);
    }
}

/* 流量分析 */
void analyseFlow(int time_pad){
    int res;
    //一个时间段结束时间
    time_t part_end_time = first_catch_time;
    while((last_catch_time - part_end_time) > 0){

        time_t end = part_end_time + time_pad;
        if(end > last_catch_time){
            end = last_catch_time;
        }
        res = fillHashTable(part_end_time, end);
        if(res == 0){
            printFlowAnalyseRes(part_end_time, end);
        }else{
            printf("该阶段分析出现错误\n");
        }

        part_end_time += time_pad;
    }

    if(last_catch_time == first_catch_time){
        res = fillHashTable(first_catch_time, last_catch_time);
        if(res == 0){
            printFlowAnalyseRes(first_catch_time, last_catch_time);
        }else{
            printf("该阶段分析出现错误\n");
        }
    }
}

/* 打印流量分析结果 */
void printFlowAnalyseRes(time_t start_time, time_t end_time){
    //时间格式转换
    struct tm start_tm, end_tm;
    char start_str[30], end_str[30];
    start_tm = *localtime(&start_time);
    end_tm = *localtime(&end_time);
    sprintf(start_str, "%4.4d.%2.2d.%2.2d-%2.2d:%2.2d:%2.2d",
            start_tm.tm_year+1900, start_tm.tm_mon+1, start_tm.tm_mday,
            start_tm.tm_hour, start_tm.tm_min, start_tm.tm_sec);
    sprintf(end_str, "%4.4d.%2.2d.%2.2d-%2.2d:%2.2d:%2.2d",
            end_tm.tm_year+1900, end_tm.tm_mon+1, end_tm.tm_mday,
            end_tm.tm_hour, end_tm.tm_min, end_tm.tm_sec);
    printf("\n\t******** %s -> %s ********\n", start_str, end_str);

    int i = 0;
    for(;i < PROTOCOL_COUNT;i++){
        int index = getProtocolLinkIndex(protocols[i]);
        printf("%s:\t", protocols[i]);
        HASH_TABLE *table = &hashTable[index];
        HASH_NODE *node = table->table_head;

        if(node == NULL){
            printf("未抓取到该协议数据包\n\n");
        }else{
            //每秒比特数、数据包数量
            unsigned int up_bps = 0;
            unsigned int up_pps = 0;
            unsigned int up_packet_count = 0;
            unsigned int down_bps = 0;
            unsigned int down_pps = 0;

            int count = table->node_count;
            int j;
            for(j = 0;j < count;j++){
                if(strcmp(local_ip, node->src_ip_addr) == 0){       //上行
                    up_bps += node->packet_len;
                    up_pps++;
                }else if(strcmp(local_ip, node->dest_ip_addr) == 0){       //下行
                    down_bps += node->packet_len;
                    down_pps++;
                }

                node = node->next;
            }

            int time_pad = 1;
            if(end_time > start_time){
                time_pad = end_time - start_time;
            }
            printf("上行bps:%db/s\t上行pps:%d个\n", (up_bps *8) / time_pad, up_pps);
            printf("\t下行bps:%db/s\t\t下行pps:%d个\n", (down_bps *8) / time_pad, down_pps);

        }
    }
}
