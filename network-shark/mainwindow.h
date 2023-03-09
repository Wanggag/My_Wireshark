#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "winsock2.h"
#include "datapackage.h"
#include <QVector>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void showNetworkcard();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);

public slots:
    void handleMessage(datapackage data);
private:
    Ui::MainWindow *ui;
    pcap_if_t* all_device;
    pcap_if_t* device;
    pcap_t* pointer;
    char errbuf[PCAP_ERRBUF_SIZE];
    QVector<datapackage>pData;
    int countNumber;
    int rowNumber;
};

#endif // MAINWINDOW_H
