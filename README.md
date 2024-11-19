# nethogs4go

实现在指定网卡上监控指定进程和相关子进程的流量，和内部商用pcdn工具统计的5分钟流量基本接近。

因libpcap采集时的cpu占用率稍高，未采用相关方案。

# 使用方式

输出路由器上有关进程每5分钟的流量
./nethogs4go.arm64 -dev=wan -pid=8543 | grep FLow

