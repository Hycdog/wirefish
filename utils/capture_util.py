import os
from scapy.all import sniff,wrpcap,Raw,IP,TCP

def get_pcap(ifs,ip=None,size=100):
    ''' 获取指定 ifs(网卡), 指定数量size 的数据包;
        如果有指定ip，则这里只接收tcp，80端口，指定ip的包 '''
    filter = ""
    if ip:
        filter += "ip src %s and tcp and tcp port 80"%ip
        dpkt = sniff(iface=ifs,filter=filter,count=size)
    else:
        dpkt = sniff(iface=ifs,count=size)
    # wrpcap("pc1.pcap",dpkt) # 保存数据包到文件
    return dpkt

if __name__ == '__main__':
    while(True):
        print(sniff(count=1).show())