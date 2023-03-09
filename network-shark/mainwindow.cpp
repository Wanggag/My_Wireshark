#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include "multhread.h"
#include <QColor>
#include <QTreeWidgetItem>
#include <QStringList>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("Welcome to CsShark!!!");
    ui->mainToolBar->addAction(ui->actionrunandstop);
//    ui->mainToolBar->addAction(ui->actionclear);
    ui->mainToolBar->setMovable(false);
    countNumber = 0;
    rowNumber = -1; //没有行被选中
    showNetworkcard();
    multhread *thread = new multhread;
    static bool index = false;
    // 显示网卡的名字
    connect(ui->actionrunandstop,&QAction::triggered,this,[=](){
        index = !index;
        
        if(index){
            ui->tableWidget->clearContents();
            countNumber = 0;
            int size = this->pData.size();
            for(int i = 0;i < size;i++){
                free((char *)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            QVector<datapackage>().swap(pData);
            int res =  capture();
            if(res!=-1 && pointer){
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                // thread->run();
                ui->actionrunandstop->setIcon(QIcon(":/Image/stop.png"));
                ui->comboBox->setEnabled(false); //开始捕获，不可在更改网卡
            }
        }else{
            //结束线程
            thread->resetFlag();
            thread->quit();
            thread->wait();
            ui->actionrunandstop->setIcon(QIcon(":/Image/start.png"));
            ui->comboBox->setEnabled(true);
            pcap_close(pointer);
            pointer = nullptr;
        }
    });

    // connect连接信号和槽函数
    connect(thread,&multhread::send,this,&MainWindow::handleMessage);

    // ui设计
    ui->tableWidget->setColumnCount(7); // 7列
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30); // 设置表格的行和高
    // 信息的标签
    QStringList title = {"No.","Time","Src","Des","Pro","Len","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    // 信息栏的大小
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);
    // 界面的
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);
}

MainWindow::~MainWindow()
{
    int datasize = pData.size();
    for(int i=0;i < datasize;i++){
        free((char *)(this->pData[i].pkt_content));
        this->pData[i].pkt_content = nullptr;
    }
    QVector<datapackage>().swap(pData);
    delete ui;
}

// 显示网卡驱动
void MainWindow::showNetworkcard()
{
   int n = pcap_findalldevs(&all_device,errbuf);
   if(n == -1){
       ui->comboBox->addItem("错误：" + QString(errbuf));
   }else{
       ui->comboBox->clear();
       ui->comboBox->addItem("请选择网卡！");
       for(device = all_device;device!=nullptr;device = device->next){
           QString device_name = device->name;
           device_name.replace("\\Device\\","");
           QString des = device->description;
           QString item = device_name + des;
           ui->comboBox->addItem(item);
       }
   }

}


void MainWindow::on_comboBox_currentIndexChanged(int index)
{
     int i =0;
     if(index!=0){
         for(device = all_device;i<index-1;device = device->next,i++);
     }
     return;
}



//捕获
int MainWindow::capture(){
    if(device){
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    }else{
        return -1;
    }
    if(!pointer){
        pcap_freealldevs(all_device);// 释放内存
        device = nullptr; // 防止野指针
        return -1;
    }else{
        if(pcap_datalink(pointer)!= DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_device);
            device = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }

    return 0;
}

// 处理数据的槽函数
void MainWindow::handleMessage(datapackage data){
    ui->tableWidget->insertRow(countNumber);
    this->pData.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if(type == "ARP")
        color = QColor(211,211,110);
    if(type == "TCP")
        color = QColor(226,190,181);
    if(type == "UDP")
        color = QColor(118,215,211);
    if(type == "DNS")
        color = QColor(102,238,188);
    if(type == "ICMP")
        color = QColor(111,111,189);
//    else
//        color = QColor(167,168,198);
    // 将数据显示到控件
    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber+1)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTime()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSrc()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDes()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackgroundColor(color);
    }
//    ui->tableWidget->item(countNumber,4)->setBackgroundColor(color);
    countNumber++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{

    if(row == rowNumber || row < 0){
        return;
    }else{
        ui->treeWidget->clear();
        ui->textBrowser->clear();
        rowNumber = row;
        if(rowNumber <0 || rowNumber > countNumber)
            return;
        QString desMac = pData[rowNumber].getDes();
        QString srcMac = pData[rowNumber].getSrcMacAddr();
        QString type = pData[rowNumber].getMacType();
        QString tree = "Ethernet,Src: " + srcMac + "  Dst: " + desMac;
        QTreeWidgetItem *item = new QTreeWidgetItem(QStringList()<< tree);
        ui->treeWidget->addTopLevelItem(item);
        item->addChild(new QTreeWidgetItem(QStringList()<< "Dst：" + desMac));
        item->addChild(new QTreeWidgetItem(QStringList()<< "Src：" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<< "Type：" + type));
        QString packageType = pData[rowNumber].getPackageType();
        if(packageType == "ARP"){
            QString op =pData[rowNumber].getArpOperationCode();
            QTreeWidgetItem *item2 = new QTreeWidgetItem(QStringList()<<"ARP: " + op);
            ui->treeWidget->addTopLevelItem(item2);
            QString HardwareType = pData[rowNumber].getArpHardwareType();
            QString protocolType = pData[rowNumber].getArpProtocolType();
//            QString HardwareSize = pData[rowNumber].getArpHardwareLength();
//            QString protocolSize = pData[rowNumber].getArpProtocolLength();
            QString srcMacAddr = pData[rowNumber].getArpSourceEtherAddr();
            QString desMacAddr = pData[rowNumber].getArpDestinationEtherAddr();
            QString srcIpAddr = pData[rowNumber].getArpSourceIpAddr();
            QString desIpAddr = pData[rowNumber].getArpDestinationIpAddr();
            item2->addChild(new QTreeWidgetItem(QStringList()<<"硬件类型: " + HardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"上层协议: " + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"操作码: " + op));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"源Mac: " + srcMac));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"源Ip: " + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"目的Mac: " + desMac));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"目的Ip: " + desIpAddr));

//            QTreeWidgetItem *item4 = new QTreeWidgetItem(QStringList()<<"Data: " );
//            ui->treeWidget->addTopLevelItem(item4);
//            QString arpdata = pData[rowNumber].getArpData(60);
//            item4->addChild(new QTreeWidgetItem(QStringList()<<arpdata));
//            char *a =pData[rowNumber].getArpData();
//            for(int i=0;i<42;i++){
//                ui->textBrowser->append(a[i]);
//            }
            ui->textBrowser->append("Arp数据报信息：");
            ui->textBrowser->append(pData[rowNumber].getArpData());
            return;
        }else{
            QString srcIp = pData[rowNumber].getSrcIPAddr();
            QString desIp = pData[rowNumber].getDesIpAddr();
            QTreeWidgetItem *item3 = new QTreeWidgetItem(QStringList()<<"IPv4,Src: " + srcIp + " Dst: " + desIp);
            ui->treeWidget->addTopLevelItem(item3);
            QString version = pData[rowNumber].getIpVersion();
            QString headrLength = pData[rowNumber].getIpHeaderLength();
            QString totalLength = pData[rowNumber].getIpTotalLength();
            QString id = "0x" + pData[rowNumber].getIpIdentification();
            QString checksum = "0x" + pData[rowNumber].getIpCheckSum();
            QString flags = pData[rowNumber].getIpFlag();
            if(flags.size()>2){
                flags = "0" + flags;
            }
            flags = "0x" + flags;
            QString off = pData[rowNumber].getIpFragmentOffset();
            QString ttl = pData[rowNumber].getIpTTL();
            QString protocol = pData[rowNumber].getIpProtocol();
            int data_length = totalLength.toUtf8().toInt() - 20; // 减去20字节的首部信息
            QString datalength = QString::number(data_length);
            item3->addChild(new QTreeWidgetItem(QStringList()<<"版本：" + version));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"首部长度：" + headrLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"总长度：" + datalength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"标识：" + id));
            QString reservedBit = pData[rowNumber].getIpReservedBit();
            QString DF = pData[rowNumber].getIpDF();
            QString MF = pData[rowNumber].getIpMF();
            QString FLAG = ",";
            if(reservedBit == "1") {
                FLAG += "Reserved bit";
            } else if(DF == "1") {
                FLAG += "Don't fragment";
            } else if(MF == "1") {
                FLAG += "More fragment";
            }
            else{
                FLAG += "最后一片";
            }
            if(FLAG.size() == 1)
                FLAG = "";
            QTreeWidgetItem *bitTree = new QTreeWidgetItem(QStringList()<<"标志位: " + flags + FLAG);
            item3->addChild(bitTree);
            ui->textBrowser->append("IP数据报信息：");
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"DF: " + DF));
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"MF: " + MF));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"片偏移 :" + off));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"TTL: " + ttl));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"上层协议: " + protocol));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"首部校验和: " + checksum));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"源Ip: " + srcIp));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"目的Ip:" + desIp));
            ui->textBrowser->append(pData[rowNumber].getIpData(data_length));
        }
    }
}

