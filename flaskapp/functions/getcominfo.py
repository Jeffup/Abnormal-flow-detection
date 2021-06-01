# -*- coding: utf-8 -*-
# tips:
from time import sleep
from psutil import net_if_addrs, cpu_percent, cpu_times, virtual_memory, net_io_counters, disk_partitions, disk_usage
from socket import *
from threading import Thread


def bytes2human(n, mode=0):
    '''
    input bytes2human(10000)
    get '9.8 K'
    input bytes2human(100001221)
    get '95.4 M'
    if mode == 0 then return str
    else if mode ==1 then return num+unit
    else if mode ==2 then return num+unit(K)
    :param n:
    :return:
    '''
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            if mode==0:
                return '%.2f %s' % (value, s)
            else:
                return {'value':value, 'unit':s}
        if mode==2 and s=='K':
            value = float(n) / prefix[s]
            return {'value': value, 'unit': s}

    if mode==0:
        return '%.2f B' % (n)
    else:
        return {'value':n, 'unit':'B'}

class ComInfo:
    def __init__(self):
        self._crunning=False

    def get_ip(self):
        ip = gethostbyname_ex(gethostname())
        return ip

    def get_netcard(self):
        netcard_info = []
        info = net_if_addrs()
        for k,v in info.items():
            for item in v:
                if item[0] == 2 and not item[1]=='127.0.0.1':
                    netcard_info.append((k,item[1]))
        return netcard_info

    def get_cpuinfo(self):
        # functions of Get CPU State;
        return {"cpu":cpu_percent()}

    def get_meminfo(self):
        phymem = virtual_memory()
        # line = "Memory: %5s%% %6s/%s" % (
        #     phymem.percent,
        #     str(int(phymem.used / 1024 / 1024)) + "M",
        #     str(int(phymem.total / 1024 / 1024)) + "M"
        # )
        return {"mem":phymem.percent}

    def get_diskinfo(self):
        disk = disk_partitions()
        free, used = 0 , 0
        for i in disk:
            disk_use = disk_usage(i.device)
            free+=disk_use.free
            used+=disk_use.used
        percent=float(used/(used+free))
        return {'disk': percent}

    def get_netinfo(self):
        # net_state = net_io_counters()
        net_state = net_io_counters(pernic=True)
        info = {'bytes_sent':0,'bytes_recv':0,'packets_sent':0,'packets_recv':0}#,'errin':0,'errout':0,'dropin':0,'dropout':0
        infolist=[0,0,0,0,0,0,0,0]
        # print(net_state.count())
        for i in range(8):
            for netcard in net_state.keys():
                infolist[i]+=net_state[netcard][i]
        tmpindex = 0
        for key in info.keys():
            info[key]=infolist[tmpindex]
            tmpindex+=1
        # net_state = net_state[netcard]
        # return "Sent:%s  Recv:%s"%(net_state[])
        return info

    def start_getpcinfo(self,showfun=print):
        self._crunning=True
        th = Thread(target=self._thread_of_pcinfo,kwargs={'showfun':showfun})
        th.start()
    def stop_getpcinfo(self):
        self._crunning=False
    # socketio线程：发送pc信息
    def _thread_of_pcinfo(self,showfun):
        olddata = self.get_netinfo()
        while self._crunning:
            global NETCARD
            cpuinfo = self.get_cpuinfo()
            meminfo = self.get_meminfo()
            diskinfo = self.get_diskinfo()
            netinfo = self.get_netinfo()
            newdata = {'bytes_sent': bytes2human((netinfo['bytes_sent']-olddata['bytes_sent'])/2 if(netinfo['bytes_sent']-olddata['bytes_sent']>0) else 0)+'/s',
                       'bytes_recv': bytes2human((netinfo['bytes_recv']-olddata['bytes_recv'])/2 if(netinfo['bytes_recv']-olddata['bytes_recv']>0) else 0)+'/s',
                       'packets_sent':bytes2human((netinfo['packets_sent']-olddata['packets_sent'])/2 if(netinfo['packets_sent']-olddata['packets_sent']>0) else 0)+'/s',
                       'packets_recv':bytes2human((netinfo['packets_recv']-olddata['packets_recv'])/2 if(netinfo['packets_recv']-olddata['packets_recv']>0) else 0)+'/s'}
            olddata = netinfo

            newdata.update(cpuinfo)
            newdata.update(meminfo)
            newdata.update(diskinfo)
            showfun(newdata)
            sleep(2)





# def poll():
#     """Retrieve raw stats within an interval window."""
#     tot_before = net_io_counters()
#     pnic_before = net_io_counters(pernic=True)
#     # sleep some time
#     sleep(1)
#     tot_after = net_io_counters()
#     pnic_after = net_io_counters(pernic=True)
#     # get cpu state
#     cpu_state = get_cpuinfo()
#     # get memory
#     memory_state = get_meminfo()
#     return (tot_before, tot_after, pnic_before, pnic_after, cpu_state, memory_state)

# print(get_netcard())
# print(get_cpuinfo())
# print(get_meminfo())
# print(poll())
# print(get_netinfo())
# print(thread_of_pcinfo())
# ci=ComInfo()
# print(ci.get_diskinfo())
# print(ci.get_cpuinfo())
# print(ci.get_meminfo())