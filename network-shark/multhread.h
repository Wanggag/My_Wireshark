#ifndef MULTHREAD_H
#define MULTHREAD_H
#include <QThread>
#include "pcap.h"
#include <QString>
#include "datapackage.h"
#include "winsock2.h"

class multhread:public QThread
{
    Q_OBJECT
public:
    multhread();
    bool setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();
    void run() override;  
    int ethernetPackageHandle(const u_char *pkt_content,QString &info); // 读取信息
    int ippackageHandle(const u_char *pkt_content, int &ipPackage);
    int tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage);
    int udpPackageHandle(const u_char *pkt_content,QString &info);
    QString icmpPackageHandle(const u_char *pkt_content);
    QString arpPackageHandle(const u_char *pkt_content);
protected:
    static QString byteTostring(u_char *str, int size);
// 发送数据的信号
signals:
    void send(datapackage data);
private:
    pcap_t* pointer;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
};

#endif // MULTHREAD_H
