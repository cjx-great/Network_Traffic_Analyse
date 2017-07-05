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
//Э�����
#define PROTOCOL_COUNT 2
//Э������
char protocols[PROTOCOL_COUNT][7] = {"TCP", "UDP"};
HASH_TABLE hashTable[PROTOCOL_COUNT];
//ץȡ���ĵ�һ������ʱ��
time_t first_catch_time;
//ץȡ�������һ������ʱ��
time_t last_catch_time;
//����IP
char *local_ip;

typedef struct _argument{
    pcap_t *handle;
    int timeLen;
}argument;

//���߳����к���
void *thread_clock(void *argv);
//����������
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data);
//ͳ��ģʽ�µİ�������
void countMode_packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data);
//���ݱ���������
void parse(const u_char *packet_data, char *catch_time, int packet_size);
//�������ļ��Ĵ�������
int creatFile();
//����Э��������ʼ��hashtable
void initHashTable();
//�ͷ�hashtableռ���ڴ�
void freeHashTable();
//���hashtable
int fillHashTable(time_t start_time, time_t end_time);
//��ӡ�����������
void printFlowAnalyseRes(time_t start_time, time_t end_time);
//����Э������ȡ������λ��
int getProtocolLinkIndex(char *pro_name);
//�����ݰ�����hashtable
void insertIntoHash(HASH_TABLE *link, HASH_NODE *node);
//��������
void analyseFlow(int time_pad);
//�ַ����ָ��
void split(char **arr, char *str, const char *del);

int main(){
    /* ��ʼ������ */
    //��������ļ�
    if(creatFile() == -1){
        return -1;
    }

    pcap_if_t *alldevs;
    //������Ϣ������
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device;

    /* ��ȡ�����豸�б� */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, error_buffer) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", error_buffer);
        exit(1);
    }

    /* ��ӡ�б� */
    printf("�����������б�:\n");
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
        printf("\n����δ�����豸!!!\n");
        return -1;
    }

    int num;
    printf("ѡ���豸�ţ�1-%d��:",i);
    scanf("%d",&num);
    getchar();
    if(num < 1 || num > i){
        printf("���뷶Χ����\n");
        //�ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ��ת��ѡ�е������� */
    for(dev = alldevs, i=0; i < num-1 ;dev = dev->next, i++);
    /* ��ñ���IP */
    struct pcap_addr *addr = dev->addresses;
    struct sockaddr_in *sin;
    for(;addr;addr = addr->next){
        sin = (struct sockaddr_in *)addr->addr;
        if(sin->sin_family = AF_INET){
            local_ip = inet_ntoa(sin->sin_addr);
        }
    }
    /* ���豸 */
    pcap_t *devHandler;
    if ((devHandler = pcap_open(dev->name,
                                65536,    // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                                PCAP_OPENFLAG_PROMISCUOUS,      //�����������ģʽ
                                1000,   // ��ȡ��ʱʱ��
                                NULL,
                                error_buffer)) == NULL){
        fprintf(stderr,"\n��������ʧ��,��֧��%s\n", dev->name);
        //�ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ���������·�㣬ֻ������̫�� */
    if(pcap_datalink(devHandler) != DLT_EN10MB){
        fprintf(stderr,"\n�ó���ֻ������̫������֡,���豸��֧��,����ѡ�豸\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //�����������
    bpf_u_int32 net, mask;
    //��������������������
    pcap_lookupnet(dev, &net, &mask, error_buffer);

    struct bpf_program fcode;
    //char packet_filter[] = "ip or tcp or udp";  //etherҪMAC��ַ
    char packet_filter[50];
    printf("������˹���:");
    gets(packet_filter);
    /* ������˹��� */
    //������������ָ�����ַ������뵽���˳�����
    //���ĸ��������ƽ��������Ż�
    //���һ������ָ�������������������
    //��һ����fcode��ֵ
    if (pcap_compile(devHandler, &fcode, packet_filter, 1, mask) < 0){
        printf("\n���˹������ʧ��\n");
        return -1;
    }
    /* ���ù��˹��� */
    if (pcap_setfilter(devHandler, &fcode) < 0){
        printf("\n���˹�������ʧ��\n");
        return -1;
    }

    /* �������߳� */
    pthread_t clock_thread;
    argument arg;
    int argv_time;

    printf("����ץȡʱ��(��):");
    scanf("%d", &argv_time);
    arg.timeLen = (argv_time > 0) ? argv_time : 60;
    arg.handle = devHandler;
    printf("ץȡʱ����%d s\n", arg.timeLen);
    //argument�ṹ�崫��
    if(pthread_create(&clock_thread, NULL, thread_clock, &arg)){
        printf("�̴߳���ʧ��\n");
        return -1;
    }

    printf("\n���ڼ���:%s...\n", dev->description);

    /* �ͷ��豸�б� */
    pcap_freealldevs(alldevs);

    /* ��ʼ���� */
    //�ڶ�����ָ����������ݰ�����,���Ϊ-1������ѭ������
    //ץ�����ݰ���ִ��packet_handler�ص�����
    printf("id\ttime\t\t\tlength\tdata\n");
    pcap_loop(devHandler, -1, packet_handler, NULL);

    /* �رմ��� */
    pcap_close(devHandler);
    printf("\n\t\t---ץȡ����---\n\n");

    /* ��������Э�����鿴���� */
    printf("Ŀǰ֧�ֵ�Э��:");
    int j;
    for(j = 0;j < PROTOCOL_COUNT;j++){
        printf("%s\t", protocols[j]);
    }
    printf("\n");
    getchar();

    //��ʼ��hash��
    initHashTable();

    int time_pad;
    printf("\n\t\t-----�鿴�����������----\n\n");
    while(1){
        printf("����ʱ����(��)('-1'����):");
        scanf("%d", &time_pad);
        getchar();

        if(time_pad == -1){
            break;
        }
        //��������Ƿ�Ϸ�
        if(time_pad > arg.timeLen){
            printf("�������!!!ʱ�������ܴ���ץȡʱ��%ds\n\n", arg.timeLen);
            continue;
        }

        analyseFlow(time_pad);
    }

    printf("\n���н���\n\n");

    return 0;
}

/* ���߳����к��� */
void *thread_clock(void *argv){
    //ʹ�����ɷ������߳�
    pthread_detach(pthread_self());

    pcap_t *handle = ((argument*)argv)->handle;
    int timeLen = ((argument*)argv)->timeLen;
    //��λ�Ǻ���
    Sleep(timeLen*1000);
    //ֹͣץ��
    pcap_breakloop(handle);
}

/* ����������
   ���һ������ָ��һ���ڴ�ռ䣬����ռ��д�ŵľ���pcap_loopץ�������ݰ�
   �ڶ��������ṹ������pcap_loop�Լ����ģ�����ȡ��һЩ�������ݰ�����Ϣ */
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data){
    struct tm _tm;
    char time[20];
    time_t local_tv_sec;
    static int id = 0;

    //��ʱ���ת���ɿ�ʶ��ĸ�ʽ
    local_tv_sec = header->ts.tv_sec;
    _tm = *localtime(&local_tv_sec);
    sprintf(time, "%4.4d.%2.2d.%2.2d-%2.2d:%2.2d:%2.2d",
        _tm.tm_year+1900, _tm.tm_mon + 1, _tm.tm_mday,
        _tm.tm_hour, _tm.tm_min, _tm.tm_sec );

    //strftime(time, sizeof(time), "%H:%M:%S", _tm);

    //��¼ץ��ʱ��
    if(id == 0){
        first_catch_time = local_tv_sec;
    }
    last_catch_time = local_tv_sec;

    /* ��Ļ��� */
    //len��ʾ���ݰ���ʵ�ʳ���
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

    /* ���ݰ����� */
    parse(packet_data, time, header->len);

}

int creatFile(){
    /* ��������Ԫ�顱�ļ� */
    remove(FILE_NAME);
    FILE *f;
    f = fopen(FILE_NAME, "w+");
    if(f == NULL){
        printf("\n����ļ�����ʧ��!!\n");
        return -1;
    }
    fprintf(f, "���\t");
    fprintf(f, "ȷ�����\t");
    fprintf(f, "���λ\t\t\t");
    fprintf(f, "ԴIP\t\t\t");
    fprintf(f, "Ŀ��IP\t\t\t");
    fprintf(f, "Դ�˿�\t\t");
    fprintf(f, "Ŀ�Ķ˿�\t");
    fprintf(f, "Э��\t");
    fprintf(f, "���ݴ�С\n");

    fclose(f);

    /* ����������������ļ� */
    char fileName[10];
    int i = 0;
    for(;i < PROTOCOL_COUNT;i++){
        sprintf(fileName, "%s.txt", protocols[i]);
        remove(fileName);
        FILE *flow = fopen(fileName, "w+");
        if(flow == NULL){
            fprintf("%sЭ�����������ļ�����ʧ��!!\n", protocols[i]);
            return -1;
        }
        fclose(flow);
    }

    return 0;
}

/* �������ݰ� */
void parse(const u_char *packet_data, char *catch_time, int packet_size){
    /* ���IP���ݰ�ͷ�� */
    IP_HEADER *ip;
    unsigned int protocol;
    unsigned int ip_head_len;
    unsigned int ip_total_len;

    //��̫��ͷ��ռ14�ֽ�
    ip = (IP_HEADER *)(packet_data + 14);
    //���ݰ�Э��
    protocol = *((unsigned int *)(&ip->protocol)) & 0xff;
    //IPͷ������
    ip_head_len = (ip->version_headLength & 0xf)*4;
    //IP�ܳ���
    ip_total_len = ntohs(ip->total_length);
    //���ݰ�����
    unsigned int packet_len = ip_total_len - ip_head_len;
    //ԴIP
    char src_ip[50];
    sprintf(src_ip, "%d.%d.%d.%d",
            ip->src_ip_address.byte1,
            ip->src_ip_address.byte2,
            ip->src_ip_address.byte3,
            ip->src_ip_address.byte4);
    //Ŀ��IP
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
    //���ݳ���
    unsigned int data_len;
    char flag_str[100];
    char pro_name[5];

    /* �̶���ʽд����������ͳ���ļ� */
    /* ץȡʱ��@ԴIP@Ŀ��IP@Դ�˿�@Ŀ�Ķ˿�@���ݰ����� */
    char file_node[100];
    strcpy(file_node, catch_time);
    strcat(file_node, "@");
    strcat(file_node, src_ip);
    strcat(file_node, "@");
    strcat(file_node, dest_ip);
    strcat(file_node, "@");

    int index;
    if(protocol == IP_TCP){             //TCPЭ�鱨ͷ
        /* ���TCP�ײ� */
        TCP_HEADER *tcp;
        tcp = (TCP_HEADER *)((unsigned char *)ip + ip_head_len);

        //�������ֽ�˳��(���)ת��Ϊ�����ֽ�˳��С�ˣ�
        //���ģʽ�����λ�ŵ͵�ַ
        //С��ģʽ�����λ�ŵ͵�ַ
        src_port = ntohs(tcp->src_port);
        dest_port = ntohs(tcp->dest_port);
        ack = ntohs(tcp->ack);
        sequence = ntohs(tcp->sequence);
        //TCP�ײ�����
        unsigned short hrf = ntohs(tcp->headlen_retain_flag);
        unsigned int tcp_head_len = ((hrf & 0xf000) >> 12)*4;
        //TCP���ݳ���
        data_len = packet_len - tcp_head_len;
        //���
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

    }else if(protocol == IP_UDP){                //UDPЭ�鱨ͷ
        /* ���UDP�ײ� */
        UDP_HEADER *udp;
        udp = (UDP_HEADER *)((unsigned char *)ip + ip_head_len);

        //�������ֽ�˳��ת��Ϊ�����ֽ�˳��
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
        // TODO ����Э��
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
        printf("\n�����ݰ�д�����������ļ�ʧ��\n\n");
    }else{
        fprintf(flow, file_node);
    }
    fclose(flow);

    /* �̶���ʽд�����ݰ���¼�ļ� */
    FILE *f;
    f = fopen(FILE_NAME, "a+");
    if(f == NULL){
        printf("\n�����ݰ�д���ļ�ʧ��\n");
    }else{
        char buffer[50];
        //���
        sprintf(buffer, "%d\t", sequence);
        fprintf(f, buffer);
        //ȷ�����
        sprintf(buffer, "%d\t\t", ack);
        fprintf(f, buffer);
        //���λ
        sprintf(buffer, "%s\t", flag_str);
        fprintf(f, buffer);
        //ԴIP
        fprintf(f, src_ip);
        fprintf(f, "\t\t");
        //Ŀ��IP
        fprintf(f, dest_ip);
        fprintf(f, "\t\t");
        //Դ�˿�
        sprintf(buffer, "%d\t\t",src_port);
        fprintf(f, buffer);
        //Ŀ�Ķ˿�
        sprintf(buffer, "%d\t\t",dest_port);
        fprintf(f, buffer);
        //Э��
        fprintf(f, pro_name);
        fprintf(f, "\t");
        //���ݰ���С
        sprintf(buffer, "%d", data_len);
        fprintf(f, buffer);
        fprintf(f, "\n");
    }
    fclose(f);

    //��ӡIP
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

/* ��ʼ��hashtable */
void initHashTable(){
    int i;
    for(i = 0;i < PROTOCOL_COUNT;i++){
        hashTable[i].table_head = NULL;
        hashTable[i].node_count = 0;
    }
}

/* ����Э������ȡ������λ�� */
int getProtocolLinkIndex(char *pro_name){
    int i = 0;
    for(;i < PROTOCOL_COUNT;i++){
        if(strcmp(pro_name, protocols[i]) == 0){
            return i;
        }
    }

    return -1;
}

/* �����ݰ�����hashtable */
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

/* �ͷ�ǰһ��hashtableռ���ڴ� */
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

/* ���hashtable */
int fillHashTable(time_t start_time, time_t end_time){
    freeHashTable();

    /* ץȡʱ��@ԴIP@Ŀ��IP@Դ�˿�@Ŀ�Ķ˿�@���ݰ����� */
    int i = 0;
    char file_name[7];
    for(;i < PROTOCOL_COUNT;i++){
        sprintf(file_name, "%s.txt", protocols[i]);
        //���ж��ļ����Ƿ�������
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
                //�ַ����ָ�
                char delims[] = "@";
                char *myArray[6];
                memset(myArray, 0x0, sizeof(myArray));
                split(myArray, file_node, delims);

                if(myArray[1] != NULL){
                    //ʱ���ж�
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
                    //�������
                    if((catch_time >= start_time)&&(catch_time <= end_time)){
                        /* ץȡʱ��@ԴIP@Ŀ��IP@Դ�˿�@Ŀ�Ķ˿�@���ݰ����� */
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

/* �������� */
void analyseFlow(int time_pad){
    int res;
    //һ��ʱ��ν���ʱ��
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
            printf("�ý׶η������ִ���\n");
        }

        part_end_time += time_pad;
    }

    if(last_catch_time == first_catch_time){
        res = fillHashTable(first_catch_time, last_catch_time);
        if(res == 0){
            printFlowAnalyseRes(first_catch_time, last_catch_time);
        }else{
            printf("�ý׶η������ִ���\n");
        }
    }
}

/* ��ӡ����������� */
void printFlowAnalyseRes(time_t start_time, time_t end_time){
    //ʱ���ʽת��
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
            printf("δץȡ����Э�����ݰ�\n\n");
        }else{
            //ÿ������������ݰ�����
            unsigned int up_bps = 0;
            unsigned int up_pps = 0;
            unsigned int up_packet_count = 0;
            unsigned int down_bps = 0;
            unsigned int down_pps = 0;

            int count = table->node_count;
            int j;
            for(j = 0;j < count;j++){
                if(strcmp(local_ip, node->src_ip_addr) == 0){       //����
                    up_bps += node->packet_len;
                    up_pps++;
                }else if(strcmp(local_ip, node->dest_ip_addr) == 0){       //����
                    down_bps += node->packet_len;
                    down_pps++;
                }

                node = node->next;
            }

            int time_pad = 1;
            if(end_time > start_time){
                time_pad = end_time - start_time;
            }
            printf("����bps:%db/s\t����pps:%d��\n", (up_bps *8) / time_pad, up_pps);
            printf("\t����bps:%db/s\t\t����pps:%d��\n", (down_bps *8) / time_pad, down_pps);

        }
    }
}
