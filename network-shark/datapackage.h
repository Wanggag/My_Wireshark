#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include "format.h"
#include <QString>

class datapackage
{
private:
    u_int data_length;
    QString time;
    QString info;
    int package_type;
protected:
    static QString  byteTostring(u_char *str,int size); //转换位16进制的函数
public:
    const u_char *pkt_content; // 将指针定义位public,all都可以访问
public:
    datapackage();
    // 获取数据包信息的函数
    void setDataLength(u_int data_length);
    void setTime(QString time);
    void setPackageType(int package_type);
    void setInfo(QString info);
    void setPointer(const u_char* pkt_content,int size);

    QString getDataLength();
    QString getTime();
    QString getPackageType();
    QString getInfo();
    QString getSrc();
    QString getDes();
    // MAC_info
    QString getMacType();
    QString getDesMacAddr();
    QString getSrcMacAddr();

    // ip_info
    QString getDesIpAddr();
    QString getSrcIPAddr();
    QString getIpVersion();
    QString getIpHeaderLength();

    QString getIpTos();
    QString getIpTotalLength();
    QString getIpIdentification();
    QString getIpFlag();
    QString getIpReservedBit();
    QString getIpDF();
    QString getIpMF();
    QString getIpFragmentOffset();
    QString getIpTTL();
    QString getIpProtocol();
    QString getIpCheckSum();
    QString getIpData(int size);

    //arp_info
    QString getArpHardwareType();
    QString getArpProtocolType();
    QString getArpHardwareLength();
    QString getArpProtocolLength();
    QString getArpOperationCode();
    QString getArpSourceEtherAddr();
    QString getArpSourceIpAddr();
    QString getArpDestinationEtherAddr();
    QString getArpDestinationIpAddr();
    QString getArpData();
    QString getArplen();

    //icmp_info
//    QString getIcmpType();
//    QString getIcmpCode();
//    QString getIcmpCheckSum();
//    QString getIcmpIdentification();
//    QString getIcmpSequeue();
//    QString getIcmpData(int size);
};

#endif // DATAPACKAGE_H
