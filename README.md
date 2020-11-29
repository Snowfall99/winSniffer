# winSniffer
Homework for IS301, 2020 Fall

# Function Table
- [x] 基本功能：通过指定需要监听的网卡，侦听进出本主机的数据包，并解析数据包的内容（ARP、IP、ICMP、IGMP、TCP、UDP、DHCP、HTTP）
- [x] TCP、UDP数据报的全部数据显示
- [ ] IP分片重组
- [x] 包过滤：能够侦听指定协议类型的数据包
- [ ] 包过滤：能够侦听指定源、目的地址的数据包
- [ ] 数据包查询：能够按照一定的查询条件（如数据内容包含“password”）集中显示所有符合条件的数据包
- [ ] 数据包保存：能够保存选中的数据包，保存文件具有可读性
- [ ] 文件重组：文件传输过程中，文件会被分割为若干个TCP包传送，如果抓到经本机的全部TCP包，能够将其重组还原为原始文件

# ISSUE List:

# 项目要求
1. 参考WinPcap、SharpPcap、LibPcap等类库
1. 执行Ping、Telnet、浏览网页和传输文件等操作时，Sniffer应返回正确的结果
