#include "datapackage.h"
#include <QMetaType>
#include "winsock2.h"
#include <QDebug>

datapackage::datapackage()
{
    qRegisterMetaType<datapackage>("datapackage"); // 注册类型
    // 初始化参数
    this->time = "";
    this->data_length = 0;
    this->package_type = 0;
    this->pkt_content = nullptr;

}
// 设置信息的函数
void datapackage::setInfo(QString info){
    this->info = info;
}

void datapackage::setDataLength(u_int data_length){
    this->data_length = data_length;
}

void datapackage::setPackageType(int package_type){
    this->package_type = package_type;
}

void datapackage::setTime(QString time){
    this->time = time ;
}

void datapackage::setPointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char *)malloc(size);
    if(this->pkt_content !=nullptr)
        memcpy((char *)(this->pkt_content),pkt_content,size);
    else
        this->pkt_content = nullptr;

}

// 用来返回并输出到ui界面
QString datapackage::getTime(){
    return this->time;
}

QString datapackage::getDataLength(){
    return QString::number(this->data_length); // 输出的字符，需要强转
}

QString datapackage::getInfo(){
    return this->info;
}
QString datapackage::getSrc(){
    if(this->package_type == 1 ){
        return this->getSrcMacAddr();
    }else return this->getSrcIPAddr();
}

QString datapackage::getDes(){
    if(this->package_type == 1 ){
        return this->getDesMacAddr();
    }else return this->getDesIpAddr();
}

// 选择要返回的协议的类型
QString datapackage::getPackageType(){
    switch (this->package_type) {
    case 0:
        return "IP";
    case 1:
        return "ARP";
    case 2:
        return "ICMP";
    case 3:
        return "TCP";
    case 4:
        return "UDP";
    case 5:
        return "DNS";
//    case 6:
//        return "tls";
//    case 7:
//        return "ssl";
    default:
        return "";

    }
}

QString datapackage::byteTostring(u_char *str, int size){
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


QString datapackage::getDesMacAddr(){
        ETHER_HEADER *ethernet;
        ethernet = (ETHER_HEADER*)(pkt_content);
        u_char*addr;
        if(ethernet){
            addr = ethernet->ether_des_host;
            if(addr){
                QString res = byteTostring(addr,1) + ":"
                        + byteTostring((addr+1),1) + ":"
                        + byteTostring((addr+2),1) + ":"
                        + byteTostring((addr+3),1) + ":"
                        + byteTostring((addr+4),1) + ":"
                        + byteTostring((addr+5),1);
                if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF";
                else return res;
            }
        }
        return "";
}


QString datapackage::getSrcMacAddr(){
    ETHER_HEADER*ethernet;
        ethernet = (ETHER_HEADER*)pkt_content;
        u_char*addr;
        if(ethernet){
            addr = ethernet->ether_src_host;
            if(addr){
                QString res = byteTostring(addr,1) + ":"
                        + byteTostring((addr+1),1) + ":"
                        + byteTostring((addr+2),1) + ":"
                        + byteTostring((addr+3),1) + ":"
                        + byteTostring((addr+4),1) + ":"
                        + byteTostring((addr+5),1);
                if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF";
                else return res;
            }
        }
        return "";
}


QString datapackage::getDesIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}


QString datapackage::getSrcIPAddr(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa((srcAddr.sin_addr)));
}

QString datapackage::getMacType(){
    ETHER_HEADER *eth = (ETHER_HEADER *)(pkt_content);
    u_short type = ntohs(eth->ether_type);
    if(type == 0x0800)
        return "IPv4";
    else if(type == 0x0806)
        return "ARP";
    else
        return "";
}

//IP_info
QString datapackage::getIpVersion(){
    IP_HEADER *IP = (IP_HEADER *)(pkt_content + 14);
    return QString::number(IP->versiosn_head_length >> 4);
}

QString datapackage::getIpHeaderLength(){
    IP_HEADER *IP = (IP_HEADER *)(pkt_content + 14);
    QString res = "";
    int length = IP->versiosn_head_length & 0x0F;
    if(length == 5)
        res = "20 bytes (5)";
    else
        res = QString::number(length * 5) + "bytes (" + QString::number(length) + ")";
    return res;
}

QString datapackage::getIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}

QString datapackage::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14); //Df标志位中的前两位，右移14位；
}

QString datapackage::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
}

QString datapackage::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8,16);
}

QString datapackage::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}

QString datapackage::getIpIdentification(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->identification),16);
}

QString datapackage::getIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17:return "UDP (17)";
    default:{
        return "";
    }
    }
}

QString datapackage::getIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->ttl);
}

QString datapackage::getIpTotalLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->total_length));
}

QString datapackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(bit);
}



//arp_info
QString datapackage::getArpDestinationEtherAddr(){
    ARP_HEADER*arp;
     arp = (ARP_HEADER*)(pkt_content + 14);
     u_char*addr;
     if(arp){
         addr = arp->des_eth_addr;
         if(addr){
             QString res = byteTostring(addr,1) + ":"
                     + byteTostring((addr+1),1) + ":"
                     + byteTostring((addr+2),1) + ":"
                     + byteTostring((addr+3),1) + ":"
                     + byteTostring((addr+4),1) + ":"
                     + byteTostring((addr+5),1);
             return res;
         }
     }
     return "";
}

QString datapackage::getArpSourceEtherAddr() {
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp) {
        addr = arp->src_eth_addr;
        if(addr) {
            QString res = byteTostring(addr,1) + ":"
                     + byteTostring((addr+1),1) + ":"
                     + byteTostring((addr+2),1) + ":"
                     + byteTostring((addr+3),1) + ":"
                     + byteTostring((addr+4),1) + ":"
                     + byteTostring((addr+5),1);
            return res;
        }
    }
    return "";
}

QString datapackage::getArpHardwareType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->hardware_type);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}

// arp_op
QString datapackage::getArpOperationCode(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request";
    else if(code == 2) res = "reply";
    return res;
}

// arp_hard_length
QString datapackage::getArpHardwareLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}

// arp_des_ip
QString datapackage::getArpDestinationIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->des_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}

// arp_src_ip
QString datapackage::getArpSourceIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->src_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}

// arp_pro_type
QString datapackage::getArpProtocolType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->protocol_type);
    QString res = "";
    if(type == 0x0800) res = "IPv4";
    else res = QString::number(type);
    return res;
}

// arp_pro_length
QString datapackage::getArpProtocolLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}

//打印arp数据报的内容
QString datapackage::getArpData(){
    unsigned char *arp = (unsigned char *)(pkt_content);
    QString res = "";
    unsigned char *buf = (unsigned char *)malloc(62);
//    for(int i ;i < size;i++){
//        QString str = QString::fromUtf8(arp);
//        QByteArray str1 = str.toLatin1().toHex();
//        QString data = str1;
//        qDebug()<<data;
//        res += data+"";
//        arp++;
//    }
//    for(int i;i< size;i++){
//        res += arp[i];
//        arp++;
//    }

    memcpy(buf,arp,62);
    for(int i=0;i<62;i++){
//        if(i%16 ==0 && i!=0){
//        }
        QString a =  QString(QString::asprintf("%02X ",buf[i]));

        res += a;
    }
//    qDebug()<<(buf);
    free(buf);
    return res;
}

//打印IP数据报的信息
QString datapackage::getIpData(int size){
    unsigned char *Ip = (unsigned char *)(pkt_content + 14);
    QString res = "";
    unsigned char *buf = (unsigned char *)malloc(size);
    memcpy(buf,Ip,size);
    for(int i=0;i<size;i++){
        QString a =  QString(QString::asprintf("%02X ",buf[i]));
        res += a;
    }
    free(buf);
    return res;
}
