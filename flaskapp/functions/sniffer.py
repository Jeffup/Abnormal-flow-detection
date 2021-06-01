# -*- coding: utf-8 -*-
# tips: this script aims to detect the traffic
from scapy.all import *
from threading import Thread

class Sniffer:
    def __init__(self):
        self._running = True

    def _stopfunc(self):
        return self._running
    def stop(self):
        self._running = True
    def show(self,pkt):
        # pkt.show()
        pkt.show()
        print('*******************************************************************')
        # l=lys[1]
        # dst=l.dst
        # src=l.src

    def run(self, prn=print, filter=None, iface=None):
        '''
        启动抓包线程
        :param filter: 过滤字符串
        :param prn: to deal with the pkt which sniff got
        :return:
        '''
        if self._running == True:
            self._running=False
        else:
            return
        # , 'iface':'VMware Network Adapter VMnet8'VMware Network Adapter VMnet8
        self.t = Thread(target=sniff, kwargs={"filter":filter,"prn":prn,"stop_filter":lambda s:self._running , 'iface':iface})
        self.t.start()



