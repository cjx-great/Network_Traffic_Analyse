# Network_Traffic_Analyse
网络流量在线分析系统的设计与实现（C语言）

该系统具有以下功能： 
（1）实时抓取网络数据。 
（2）网络协议分析与显示。 
（3）将网络数据包聚合成数据流，以源IP、目的IP、源端口、目的端口及协议等五元组的形式存储。 
（4）计算并显示固定时间间隔内网络连接（双向流）的统计量（如上行与下行的数据包数目，上行与下行的数据量大小等）。
    在这些统计数据的基础上分析不同网络应用的流量特征。

详细内容： 
（1）能够实时抓取网络中的数据包。并实时显示在程序界面上。用户可自定义过滤条件以抓取所需要的数据包。
（2）分析各个网络协议格式，能够显示各协议字段的实际意义。例如，能够通过该程序反映TCP三次握手的实现过程。 
（3）采用Hash链表的形式将网络数据以连接（双向流）的形式存储。
（4）计算并显示固定时间间隔内网络连接（双向流）的统计量（如上行与下行的数据包数目，上行与下行的数据量大小等）。
    例如，抓取一段时间（如30分钟）的网络流量，将该段时间以固定时长（如1分钟）为单位分成若干个时间片， 计算网络连接在每一个时间片内的相关统计量。
    并在上述统计数据的基础上分析不同应用如WEB、DNS、在线视频等服务的流量特征。