#include "multhread.h"
#include <QDebug>
#include "format.h"
#include "datapackage.h"
#include <QVector>

multhread::multhread()
{
    this->isDone = true;
    this->pkt_data = nullptr;
    this->pointer = nullptr;
    this->header = nullptr;
}

bool multhread::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer){
        return true;
    }else
        return false;
}

void multhread::setFlag(){
    this->isDone = false;
}

void multhread::resetFlag(){
    this->isDone = true;
}
// 转化为16进制的函数
QString multhread::byteTostring(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char high = str[i] >> 4;
        if(high >= 0x0A)
            high += 0x41 - 0x0A;
        else
            high += 0x30;
        char low = str[i] & 0xf;
        if(low >= 0x0A)
            low += 0x41 - 0x0A;
        else
            low += 0x30;
        res.append(high);
        res.append(low);
    }
    return res;
}

void multhread::run(){
    unsigned int number_package = 0;
    while(true){
        if(isDone)
            break;
        int res = pcap_next_ex(pointer,&header,&pkt_data);
        if(res == 0)
            continue;
        // 获取当前的时间戳信息
        local_time_sec = header->ts.tv_sec;
        localtime_s(&local_time,&local_time_sec);
        strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);
        QString info = "";
        int type = ethernetPackageHandle(pkt_data,info);
        if(type){
             datapackage data;
             int len = header->len;
             data.setInfo(info);
             data.setDataLength(len);
             data.setTime(timeString);
             data.setPackageType(type);
             data.setPointer(pkt_data,len);
             if(data.pkt_content != nullptr){
                emit send(data);
                number_package++;
            }else continue;
        }
        else continue;
    }
    return ;
}

int multhread::ethernetPackageHandle(const u_char *pkt_content, QString &info){
    ETHER_HEADER *ethenet = (ETHER_HEADER *)pkt_content;
    u_short context_type;
    context_type = ntohs(ethenet->ether_type); //net -> host
    switch(context_type){
    case 0x0800:{
        int ipPackage = 0; // 定义ip包的长度，先设置为0
        int res = ippackageHandle(pkt_content,ipPackage);
        switch(res){
        case 1:{//icmp
            info = icmpPackageHandle(pkt_content);
            return 2;
            break;
        }
        case 6:{ //tcp
            return tcpPackageHandle(pkt_content,info,ipPackage);
        }
        case 17:{ //udp
            return udpPackageHandle(pkt_content,info);   
        }
        default:break;
        }
        break;
    }
    case 0x0806:{
        info = arpPackageHandle(pkt_content);
        return 1;
    }
    default:
        break;
    }
    return 0;
}

// 获取IP上层协议
int multhread::ippackageHandle(const u_char *pkt_content, int &ipPackage){
    IP_HEADER *ip = (IP_HEADER *)(pkt_content + 14);
    int pro = ip->protocol;
    ipPackage = (htons(ip->total_length) - 4*(ip->versiosn_head_length)&0x0f);
    return pro;
}

int multhread::tcpPackageHandle(const u_char *pkt_content, QString &info, int ipPackage){
    TCP_HEADER *tcp = (TCP_HEADER *)(pkt_content + 34); // 跳过mac和ip
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);
    QString prosend = " ";
    QString prorecv = " ";
    int type = 3; // 3表示为tcp
    int delta = (tcp->header_length >> 4) * 4;
    int load = ipPackage - delta;

    if(src == 443 || des == 443){
        if(src == 443)
            prosend = "(https)";
        else prorecv = "(https)";
    }
    info += QString::number(src) + prosend + "->" + QString::number(des) + prorecv;
    QString flags = "";
    if(tcp->flags & 0x08) flags = "PSH,";
    if(tcp->flags & 0x10) flags = "ACK,";
    if(tcp->flags & 0x02) flags = "SYN,";
    if(tcp->flags & 0x20) flags = "URG,";
    if(tcp->flags & 0x01) flags = "FIN,";
    if(tcp->flags & 0x04) flags = "RST,";
    if(flags != ""){
        flags = flags.left(flags.length()-1);
        info += "{" + flags +"} ";
    }
    u_int seq = ntohl(tcp->sequence);
    u_int ack = ntohl(tcp->ack);
    u_short win = ntohs(tcp->window_size);
    info += "seq=" + QString::number(seq) + " ack=" + QString::number(ack) + " win_size=" + QString::number(win);
    return type;
}

int multhread::udpPackageHandle(const u_char *pkt_content, QString &info){
    UDP_HEADER *udp = (UDP_HEADER *)(pkt_content + 34);
    u_short des = ntohl(udp->des_port);
    u_short src = ntohl(udp->src_port);
    if(des == 53 || src == 53){
        return 5; // 端口为53表示为DNS
    }else{
        u_short len = ntohs(udp->data_length);
        QString res = QString::number(src) + " -> " + QString::number(des);
        res += " len=" + QString::number(len);
        info = res;
        return 4; // 返回udp
    }
}

QString multhread::arpPackageHandle(const u_char *pkt_content){
    ARP_HEADER *arp = (ARP_HEADER *)(pkt_content + 14);
    u_short op = ntohs(arp->op_code); //获取操作码，send or recieve
    QString res = " ";
    // des_ip
    u_char * des_ip = arp->des_ip_addr; //通过指针向后移动来取地址
    QString desIp = QString::number(*des_ip) + "."
            + QString::number(*(des_ip + 1)) + "."
            + QString::number(*(des_ip + 2)) + "."
            + QString::number(*(des_ip + 3));
    //src_ip
    u_char * src_ip = arp->src_ip_addr; //通过指针向后移动来取地址
    QString srcIp = QString::number(*src_ip) + "."
            + QString::number(*(src_ip + 1)) + "."
            + QString::number(*(src_ip + 2)) + "."
            + QString::number(*(src_ip + 3));
    //src_mac
    u_char *src_mac = arp->src_eth_addr;
    QString srcMac = byteTostring(src_mac,1) + ":"
            + byteTostring((src_mac + 1),1) + ":"
            + byteTostring((src_mac + 2),1) + ":"
            + byteTostring((src_mac + 3),1) + ":"
            + byteTostring((src_mac + 4),1) + ":"
            + byteTostring((src_mac + 5),1);
    if(op ==1){ // 请求
        res = "who has " + desIp +"? tell " + srcIp;
    }else if(op == 2){ // 应答
        res = srcIp + " is at " + srcMac;
    }
    return res;
}

QString multhread::icmpPackageHandle(const u_char *pkt_content) {
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 20 + 14);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString result = "";
    switch (type) {
        case 0: {
            if(!code)
                result = "Echo response (ping)";
            break;
        }
        case 8: {
            if(!code)
                result = "Echo request (ping)";
            break;
        }
        default:
            break;
    }
    return result;
}


