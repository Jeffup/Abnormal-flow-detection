# -*- coding: utf-8 -*-
# tips:

from queue import *
from time import strftime,sleep,localtime
# from getcominfo import *
from config import *
from functions.mysqlctl import create_session, initdb, dropdb, recreate, EVENT_ALARM, EVENT_COUNT,IP_COUNT
from re import compile, I, search, S
from base64 import b64decode
from io import BytesIO
from datetime import datetime
from time import mktime
from urllib.parse import unquote
import gzip
from sqlalchemy import func,text
class PacketAnalysis:
    def __init__(self):
        self._BUFFER_FAILLOG={}# statistic IP
        self._BUFFER_FILE={}
        self._loadfile()
        self._BRUNUM=10      # 5times
        self._BRUTIME= 0.1# 5min

        self._DOSNUM = 100
        self._BUFFER_EVILCOUNT=0
        self._EVILNUM= 10
        self._EVILTIME=3 # if this TCP isnot respond by SA in 3 seconds, it will be taged EVIL
        self._EVILFLUSHTIME=30 # 30 seconds delect old TCP link

        self.buff_fin_port = []
        self.buff_ack_port = []
        self.buff_alltcp_port = []
        self.buff_tcp_port = []
        self.buff_non_port = []
        # create database if those db are not exist
        # initdb()
        # recreate()
    def testmysql(self):
        anlydatalist = []
        ip = '10.10.10.129'
        mac = '00:0c:29:d7:3c:b9'
        anlydata = {'ip': ip, 'mac': mac, 'anlydata': []}
        resdata = []
        # 1
        anlydata['protocol'] = 'HTTP'
        anlydata['time'] = '2021-05-19 15:21:50'
        anlydata['length'] = 148
        resdata = self._makeresdata(
            resdata=resdata,
            type='入侵',
            description='使用web渗透攻击XSS攻击，攻击代码为=><<ScRiPt>AlErT(\'XSS\')</ScRiPt>',
            detail='使用web渗透攻击XSS攻击，攻击代码为=><<ScRiPt>AlErT(\'XSS\')</ScRiPt>',
            isdeal='使用web渗透攻击XSS攻击',
            rank=1
        )
        anlydata['anlydata'] = resdata
        if anlydata == [] or anlydata['anlydata'] == []:
            return
        session = create_session()

        ipquery = session.query(IP_COUNT).filter(IP_COUNT.ip == anlydata['ip']).first()
        try:
            if ipquery == None:
                ip_count = IP_COUNT(
                    ip=anlydata['ip'],
                    mac=anlydata['mac'],
                    first_time=anlydata['time'],
                    last_time=anlydata['time'],
                    attack_count=len(anlydata['anlydata'])
                )
                session.add(ip_count)
            else:
                ipquery.last_time = anlydata['time']
                ipquery.attack_count += len(anlydata['anlydata'])
            session.commit()
        except:
            pass

        for item in anlydata['anlydata']:
            event_count = EVENT_COUNT(
                ip=anlydata['ip'],
                time=anlydata['time'],
                type=item['type'],
                protocol=anlydata['protocol'],
                length=anlydata['length'],
                description=item['description'],
                detail=item['detail']
            )
            session.add(event_count)
            if item['rank'] >= 1:
                alarmquery = session.query(EVENT_ALARM).filter(EVENT_ALARM.ip == anlydata['ip'],
                                                               EVENT_ALARM.description == item['isdeal']).first()
                if alarmquery == None:
                    event_alarm = EVENT_ALARM(
                        ip=anlydata['ip'],
                        time=anlydata['time'],
                        description=item['isdeal'],
                        isdeal='wait'
                    )
                    session.add(event_alarm)
                else:
                    if alarmquery.isdeal == 'ok' and alarmquery.dealtime - anlydata['time'] > 30:
                        alarmquery.isdeal == 'wait'
                    else:
                        alarmquery.time = anlydata['time']
            session.commit()
        session.close()

    def _makeresdata(self,resdata, type,description='暂无',detail='暂无',isdeal='暂无',rank=0):
        tmpdata = {}
        tmpdata['type'] = type
        tmpdata['description'] = description
        tmpdata['detail'] = detail
        tmpdata['isdeal']=isdeal
        tmpdata['rank'] = rank
        resdata.append(tmpdata)
        return resdata
    def _buffer_faillog_init(self, ip, proto):
        if ip not in self._BUFFER_FAILLOG:
            self._BUFFER_FAILLOG[ip]={}
        if proto not in self._BUFFER_FAILLOG[ip]:
            self._BUFFER_FAILLOG[ip][proto]=[]
        return self._BUFFER_FAILLOG[ip][proto]
    def _buffer_file_init(self, ip, port):
        if ip not in self._BUFFER_FAILLOG:
            self._BUFFER_FILE[ip]={}
        if port not in self._BUFFER_FILE[ip]:
            self._BUFFER_FILE[ip][port]=[]
        return self._BUFFER_FILE[ip][port]

    def _loadfile(self):
        with open('./functions/protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]  # 将配置文件中的信息(0257:Experimental)存入dict

        # IP:读取IP层协议配置文件
        with open('./functions/protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]  # 将配置文件中的信息(41:IPv6)存入dic

        # PORT:读取应用层协议端口配置文件
        with open('./functions/protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]  # 如：21:FTP

        # TCP:读取TCP层协议配置文件
        with open('./functions/protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]  # 465:SMTPS

        # UDP:读取UDP层协议配置文件
        with open('./functions/protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]  # 513:Who

        # Abnormaly Traffic Detection
        with open('./functions/protocol/WARN', 'r', encoding='UTF-8') as f:
            warns = f.readlines()
        self.WARN_DICT = dict()
        for warn in warns:
            warn = warn.strip()
            self.WARN_DICT[int(warn.split(':')[0])] = warn.split(':')[1]
        # this dict is to match the normal way of web attack, which including SQL/XSS injection and so on
        with open('./functions/warning/HTTP_ATTACK', 'r', encoding='UTF-8') as f:
            attacks = f.readlines()
        self.ATTACK_DICT = dict()
        for attack in attacks:
            attack = attack.strip()
            self.ATTACK_DICT[attack.split(' : ')[0]] = attack.split(' : ')[1]
    def _getprotocol(self, type, elem1, elem2=None):
        '''
        此函数用于
        :param type:包类型 （如Ether）
        :param elem1: 参数1，可以用于传入Ether
        :param elem2:
        :return:
        '''
        if type == 'Ether':
            return self.ETHER_DICT[elem1] if elem1 in self.ETHER_DICT.keys() else 'unknown'
        elif type == 'IP':
            return  self.IP_DICT[elem1] if elem1 in self.IP_DICT.keys() else 'unknown'
        elif type == 'TCP' or type == 'UDP':
            if elem1 in self.PORT_DICT.keys():
                return self.PORT_DICT[elem1]
            elif elem2 in self.PORT_DICT.keys():
                return self.PORT_DICT[elem2]
            else:
                tmpdict = self.TCP_DICT if type == 'TCP' else self.UDP_DICT
                if elem1 in tmpdict.keys():
                    return tmpdict[elem1]
                elif elem2 in tmpdict.keys():
                    return tmpdict[elem2]
                else:
                    return 'unknown'
    def pktdecode(self,pkt):
        try:
            data = {}#存储数据包解析的数据
            data['protocol']='unknown'
            data['src']=''
            data['dst']=''
            data['time']= pkt.time
            data['length']=len(pkt.original)
            # print(pkt.haslayer('HTTP'))
            # 数据包解析，层层解析
            for lys in pkt.layers():
                data[lys.__name__]={}#获得协议名，并作为字典键
                pkt_lys = pkt.getlayer(lys.__name__)#获得该协议名对应的layer
                for f in lys.fields_desc:
                    fvalue = pkt_lys.getfieldval(f.name)#根据该协议名的域中的键名提取layer中的数据
                    if f.name.find('dst')!=-1:
                        data['dst'] = fvalue
                    if f.name.find('src')!=-1:
                        data['src'] = fvalue
                    data[lys.__name__][f.name]=fvalue
                # 更新协议（根据配置文件）
                proto='unknown'
                if lys.__name__ == 'Ether':
                    proto = self._getprotocol(lys.__name__, data[lys.__name__]['type'])
                elif lys.__name__ =='IP':
                    proto = self._getprotocol(lys.__name__, data[lys.__name__]['proto'])
                elif lys.__name__ =='TCP' or lys.__name__=='UDP':
                    proto = self._getprotocol(lys.__name__, data[lys.__name__]['sport'], data[lys.__name__]['dport'])
                # else:
                #     proto = lys.__name__ if lys.__name__!='Raw' else proto
                data[lys.__name__]['proto']=proto
                data['protocol'] = proto if proto != 'unknown' else data['protocol']
                # data['protocol'] = proto if proto != 'Padding' else 'TCP'
                    # proto if proto != 'unknown' else data['protocol']
            # data['protocol'] = data['IP']['proto'] if 'IP' in data.keys() and data['protocol'] == 'IP' else data['protocol']
            data['summary'] = pkt.summary()#包的具体行为
            # if 'TCP' in data.keys() and 'Raw' in data.keys():
            #     data['Raw'] = self._http(data['Raw'])
            # 测试
            # print(data['Raw'] if 'Raw' in data.keys() else None)
            # print(data)
            # self.abnormalPktAnly(data,print)
            return data
        except Exception as e:
            print(e)
            # return None
    def pktanalysis(self, pkt):
        rawdata=self.pktdecode(pkt)

        isattack = 0 # if this value is eq 1,then i will push it into the db, else, abandon
        anlydata = {'ip':'','mac':'', 'time':'', 'length':'','protocol':'', 'port':'', }

        srcordst = 'src' if rawdata['src'] != IPADDRESS else 'dst'
        anlydata['ip']=rawdata[srcordst]
        anlydata['mac']=rawdata['Ether'][srcordst]
        anlydata['time']=strftime("%Y-%m-%d %H:%M:%S", localtime(rawdata['time']))
        anlydata['length']=rawdata['length']
        anlydata['protocol']=rawdata['protocol']

        resdata=[]
        resdata+=self._PORTWARN(rawdata)
        if anlydata['protocol']=='ARP':
            resdata+=self._ARPDETECT(rawdata)
        elif anlydata['protocol']=='ICMP':
            resdata+=self._ICMPDETECT(rawdata)
        elif 'TCP' in rawdata.keys():
            # resdata+=self._EVILFLOW(rawdata)
            if anlydata['protocol']=='HTTP':
                resdata+=self._HTTPDETECT(rawdata)
            if anlydata['protocol']=='FTP':
                resdata+=self._FTPDETECT(rawdata)
        elif 'UDP' in rawdata.keys():
            resdata+=self._UDPDETECT(rawdata)

        anlydata['anlydata']=resdata
        # if anlydata['anlydata']!=[]:
        #     print(anlydata)
        return anlydata
    def prnforsniff(self, pkt):
        anlydata = self.pktanalysis(pkt)
        if anlydata==[] or anlydata['anlydata']==[]:
            return
        print(anlydata)
        session = create_session()

        ipquery = session.query(IP_COUNT).filter(IP_COUNT.ip==anlydata['ip']).first()
        try:
            if ipquery==None:
                ip_count=IP_COUNT(
                    ip=anlydata['ip'],
                    mac=anlydata['mac'],
                    first_time=anlydata['time'],
                    last_time=anlydata['time'],
                    attack_count=len(anlydata['anlydata'])
                )
                session.add(ip_count)
            else:
                ipquery.last_time=anlydata['time']
                ipquery.attack_count+=len(anlydata['anlydata'])
            session.commit()
        except:
            pass

        for item in anlydata['anlydata']:
            if item['rank']<=1:
                event_count=EVENT_COUNT(
                    ip=anlydata['ip'],
                    time=anlydata['time'],
                    type=item['type'],
                    protocol=anlydata['protocol'],
                    length = anlydata['length'],
                    description=item['description'],
                    detail=item['detail']
                )
                session.add(event_count)
            if item['rank']>=1:
                alarmquery = session.query(EVENT_ALARM).filter(EVENT_ALARM.ip==anlydata['ip'], EVENT_ALARM.description==item['isdeal']).first()
                if alarmquery==None:
                    event_alarm=EVENT_ALARM(
                        ip=anlydata['ip'],
                        time=anlydata['time'],
                        description=item['isdeal'],
                        isdeal='wait'
                    )
                    session.add(event_alarm)
                else:
                    # alarmquery.dealtime.__dir__
                    # print(alarmquery.isdeal)
                    if alarmquery.isdeal=='ok' and mktime(datetime.strptime(anlydata['time'], "%Y-%m-%d %H:%M:%S").timetuple())-mktime(alarmquery.dealtime.timetuple())>30:
                        # thistime - dealtime
                        # print(mktime(datetime.strptime(anlydata['time'], "%Y-%m-%d %H:%M:%S").timetuple())-mktime(alarmquery.dealtime.timetuple()))
                        # print('alaem')
                        alarmquery.isdeal='wait'
                    else:
                        alarmquery.time=anlydata['time']
            session.commit()
        session.close()

    def _ICMPDETECT(self, data):
        '''
        ICMP攻击检测函数
        :param data:
        :return:
        '''
        hacker = 'src' if data['src'] != IPADDRESS else 'dst'
        ip = data[hacker]
        time = data['time']
        proto = 'ICMP'

        ICMP_ATTACK_TIME = 10  # in 10s

        buffer = self._buffer_faillog_init(ip=ip, proto=proto)
        
        resdata = []
        if data['length'] > 1450:
            resdata = self._makeresdata(
                resdata=resdata,
                type='入侵',
                description='ICMP死亡之PING,ICMP报文大小超过1450字节',
                detail=data['Raw']['load'].decode('utf-8', 'ignore'),
                isdeal='ICMP死亡之PING',
                rank=1
            )
        buffer.append({'time': time})

        evilcount = 0
        flushflag = 0
        for item in buffer:
            if time - item['time'] > ICMP_ATTACK_TIME:
                flushflag = 1
            else:
                evilcount += 1
        # print(evilcount)
        if evilcount > self._BRUNUM and flushflag == 1:
            buffer.clear()
            resdata = self._makeresdata(
                resdata=resdata,
                type='探测',
                description='ICMP持续探测',
                detail='ICMP持续探测,%ds内发送%d个ICMP包'%(ICMP_ATTACK_TIME,evilcount),
                isdeal='ICMP持续探测',
                rank=0
            )

        return resdata
    def _FTPDETECT(self,data):
        '''
        FTP暴力攻击检测
        :param data:
        :param showfun:
        :return:
        '''
        resdata = []
        if 'Raw' in data.keys() and data['protocol']=='FTP':
            # 提取用户名密码
            # revesion = compile( )#220-FileZilla Server version 0.9.43 beta
            # str = 'USER asdf'
            ip=data['src'] if data['src']!=IPADDRESS else data['dst']
            proto= 'FTP'#port==21
            time=data['time']
            
            buffer = self._buffer_faillog_init(ip=ip, proto=proto)
            reuser = r'USER\s.*'
            repwd = r'PASS\s.*'
            reappe = r'APPE\s.*'
            restor = r'STOR\s.*'
            reretr = r'RETR\s.*'
            recor = '230 Log'
            reerr = '530 Log'

            rawload = data['Raw']['load'].decode('utf-8', 'ignore')
            user = search(reuser, rawload)
            pwd = search(repwd, rawload)
            appe = search(reappe, rawload)
            stor = search(restor, rawload)
            retr = search(reretr, rawload)

            sr=compile(r'(RETR|STOR)(.*?)150', S)
            print(rawload)
            result = sr.findall(rawload)
            if result!=[]:
                resdata = self._makeresdata(
                    resdata=resdata,
                    type='敏感数据',
                    description='尝试使用FTP上传文件',
                    detail='使用命令_从FTP服务器上传文件,文件名%s' % result,
                    isdeal='尝试使用FTP上传文件',
                    rank=1
                )
            # if "PASV" in rawload:  # PASV模式,通过Web浏览器访问模式
            #     pattern_pasv = compile(r'PASV(.*?)RETR(.*?)150', S)
            #     result = pattern_pasv.findall(rawload)
            #     if not result:
            #         return resdata
            #     if 'LIST' in result[0][0]:
            #         start = 1
            #     else:
            #         start = 0
            #     port_file_list=list()
            #     for port, file in result:
            #         port = port.strip().split('(')[-1].split(')')[0].split(',')
            #         port = int(port[-2]) * 256 + int(port[-1])
            #         file = file.strip().split('/')[-1]
            #         port_file_list.append((port, file))
            #     for port, filename in port_file_list:
            #         tmpbuf = self._buffer_file_init(ip,port)
            #         if filename in tmpbuf:
            #             continue
            #         else:
            #             tmpbuf.append(filename)
            #             resdata=self._makeresdata(
            #                 resdata=resdata,
            #                 type='敏感数据',
            #                 description='尝试使用FTP上传文件',
            #                 detail='使用命令_从FTP服务器上传文件,文件名%s' % filename,
            #                 isdeal='尝试使用FTP上传文件'
            #             )
            # elif 'PORT' in rawload:  # PORT模式,通过终端访问模式
            #     pattern_port = compile(r'(RETR|STOR)(.*?)150', S)
            #     result = pattern_port.findall(rawload)
            #     port_file_list = list()
            #     for port, pattern, file in result:
            #         port = port.strip().split('\r\n')[-2].split(',')
            #         port = int(port[-2]) * 256 + int(port[-1])
            #         file = file.strip()
            #         port_file_list.append((port, file))
            #     for port, filename in port_file_list:
            #         tmpbuf = self._buffer_file_init(ip, port)
            #         if filename in tmpbuf:
            #             continue
            #         else:
            #             tmpbuf.append(filename)
            #             resdata = self._makeresdata(
            #                 resdata=resdata,
            #                 type='敏感数据',
            #                 description='尝试使用FTP上传文件',
            #                 detail='使用命令_从FTP服务器上传文件,文件名%s' % filename,
            #                 isdeal='尝试使用FTP上传文件'
            #             )

            if user is not None:
                try:
                    username = user.group().split(' ')[1]
                    username = username.split('\\')[0]
                    buffer.append({'username':username, 'password':None, 'islog':None, 'time':time})
                except:
                    pass

            if pwd is not None:
                try:
                    password = pwd.group().split(' ')[1]
                    for item in buffer:
                        if item['password'] == None:
                            item['password'] = password
                            break
                except:
                    pass
            islog=''
            if recor in rawload:
                islog='yes'
            elif reerr in rawload:
                islog='no'

            if islog!='':
                fail_count = 0
                tmpitem={'username':'','password':'','islog':None}
                for item in buffer:
                    if item['islog'] == 'no':
                        fail_count += 1
                    elif item['islog'] == None and item['password']!=None:
                        item['islog'] = islog
                        tmpitem['username'] = item['username']
                        tmpitem['password'] = item['password']
                        tmpitem['islog'] = item['islog']
                if  tmpitem['islog']=='yes':
                    buffer=[]
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='敏感信息',
                        description='尝试登录FTP服务器成功,截获登录名：%s 密码：%s'%(tmpitem['username'], tmpitem['password']),
                        detail=rawload,
                        isdeal='尝试登录FTP服务器成功',
                        rank=1
                    )
                elif tmpitem['islog']=='no':
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='敏感信息',
                        description='尝试登录FTP服务器失败,截获登录名：%s 密码：%s'%(tmpitem['username'], tmpitem['password']),
                        detail=rawload,
                        isdeal='尝试登录FTP服务器失败',
                        rank=1
                    )
                # 只是发送登录行为到EVENTALARM，而非登录账号密码
                # resdata = self._makeresdata(
                #     resdata=resdata,
                #     type='入侵',
                #     description='尝试登录FTP服务器',
                #     isdeal='尝试登录FTP服务器',
                #     rank=2
                # )
                if fail_count>self._BRUNUM:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='爆破',
                        description='爆破FTP服务器用户名密码',
                        isdeal='爆破FTP服务器',
                        rank=2
                    )
                tmp_buff = buffer[:]
                for item in buffer:
                    if time - item['time'] > self._BRUTIME:
                        tmp_buff.remove(item)
                    else:
                        break
                buffer = tmp_buff[:]
        return resdata
    # 同理得到ARP攻击警告
    def _ARPDETECT(self, data):
        '''
        ARP cheat( arpspoof ). Normally, if attacker use the tool--arpspoof, then we can detect that there are continual
        arp traffic flow into our service.
        :param data:
        :return:
        '''
        hacker = 'src' if data['src'] != IPADDRESS else 'dst'
        ip = data[hacker]
        time=data['time']
        proto='ARP'

        buffer = self._buffer_faillog_init(ip=ip, proto=proto)
        ARP_ATTACK_TIME=1 #in 10s
        resdata=[]

        buffer.append({'time': time})
        evilcount=0
        flushflag=0
        for item in buffer:
            if time-item['time']>ARP_ATTACK_TIME:
                flushflag=1
            else:
                evilcount+=1
        if evilcount > self._BRUNUM and flushflag==1:
            buffer.clear()
            resdata = self._makeresdata(
                resdata=resdata,
                type='入侵',
                description='大量ARP包,疑似ARP攻击',
                detail='%ds内发送%d个ARP包'%(ARP_ATTACK_TIME,evilcount),
                isdeal='ARP攻击',
                rank=1
            )
        return resdata

    def _PORTWARN(self,data):
        '''
        this function is to detect whether the pkt was sent though WARNING PORT
        :param data: raw_data ( after deal with pktdecode )
        :return:
        '''
        port=0
        resdata=[]
        # there are two types
        if 'TCP' in data.keys():
            port = data['TCP']['sport'] if data['src'] !=IPADDRESS else data['TCP']['dport']
        elif 'UDP' in data.keys():
            port = data['UDP']['sport'] if data['src'] !=IPADDRESS else data['UDP']['dport']
        if str(port) in self.WARN_DICT.keys():
            resdata = self._makeresdata(
                resdata=resdata,
                type='入侵',
                description='尝试使用历史恶意端口%s进行收发数据' %self.WARN_DICT[str(port)],
                detail='尝试使用历史恶意端口%d进行收发数据,该端口为%s常用端口' %(port, self.WARN_DICT[str(port)]),
                isdeal='恶意端口收发数据',
                rank=1
            )
        return resdata

    def _UDPDETECT(self, data):
        resdata = []
        hacker = 'src' if data['src'] != IPADDRESS else 'dst'
        ip = data[hacker]
        proto = 'UDP'
        time = data['time']

        port = data['UDP']['sport'] if hacker == 'dst' else data['UDP']['dport']

        buffer = self._buffer_faillog_init(ip=ip, proto=proto)
        if 'Raw' in data.keys():
            rawload=data['Raw']['load'].decode('utf-8', 'ignore')
            pattern = compile(r'([0-9a-zA-Z])\1{15}', I)
            relist = pattern.findall(rawload)
            if relist!=[]:
                buffer.append({'time':time,'port':port})
        flushflag = 0
        tmp_port=[]
        for item in buffer:
            if time - item['time'] > 0.05:   #5 seconds
                flushflag = 1
            tmp_port.append(item['port'])
        if tmp_port!=[] and flushflag==1:
            resdata = self._makeresdata(
                resdata=resdata,
                type='探测',
                description='UDP主机系统信息探测',
                detail='端口有：%s' % tmp_port,
                isdeal='端口扫描',
                rank=1
            )
            buffer.clear()
        return resdata
    def _EVILFLOW(self, data):
        '''
        this function can detect many attack tpyes ,which including SYNflood, Nmap Scan(PORT or SYSTEM)[use UDP or TCP]
        i will use other threshold value to measure if exist evil flow or not.

        :param data:
        :return:
        '''
        # dict格式：{本机端口号: {对方IP地址: {对方端口号: {‘flag’:?, 'seq':?, 'ack':?, 'time' =?, 'count':?}}}}
        # count：用于检测这个包发送了多少次（根据序列号判定），若重发4次以上（也就是重复4次），那么判定为异常数据        flags = ['S', 'SA', 'A', 'FA', 'A', 'FA', 'A']
        resdata = []
        if 'TCP' in data.keys():
            hacker = 'src' if data['src'] != IPADDRESS else 'dst'
            ip = data[hacker]
            proto = 'TCP'

            buffer = self._buffer_faillog_init(ip=ip, proto=proto)

            tcpflag = str(data['TCP']['flags'])
            seq = data['TCP']['seq']
            ack = data['TCP']['ack']
            time = data['time']
            port = data['TCP']['sport'] if hacker == 'dst' else data['TCP']['dport']

            evillink = 0
            flushflag = 0
            doslink=0

            if tcpflag == 'S':
                buffer.append({'flag': tcpflag, 'port': port, 'seq': seq, 'ack': ack, 'time': time, 'attacktype': None,
                               'changetime': 1})
            else:
                add_flag = 0
                for item in buffer:
                    if item['seq'] + 1 == ack:
                        item['seq'] = -1
                        item['flag'] = tcpflag
                        item['changetime'] += 1
                        add_flag = 1
                        break
                if add_flag == 0:
                    buffer.append(
                        {'flag': tcpflag, 'port': port, 'seq': seq, 'ack': ack, 'time': time, 'attacktype': 'evil','changetime': 0})
            for item in buffer:
                if time - item['time'] > 0.05:
                    flushflag = 1
                elif item['changetime'] == 0 or item['flag'] == 'S':
                    evillink += 1
                    if 'F' in item['flag'] and item['port'] not in self.buff_fin_port:
                        self.buff_fin_port.append(item['port'])
                elif 'A' == item['flag']:
                    pass
                    # self.buff_ack_port.append(item['port'])
                elif 'R' in item['flag']:
                    if item['changetime'] == 2 and item['port'] not in self.buff_non_port:
                        self.buff_non_port.append(item['port'])
                    elif item['changetime'] == 3 and item['port'] not in self.buff_tcp_port:
                        self.buff_tcp_port.append(item['port'])
                    elif item['changetime'] == 4 and item['port'] not in self.buff_alltcp_port:
                        self.buff_alltcp_port.append(item['port'])
                    else:
                        evillink+=1
                if item['attacktype']=='evil':
                    evillink += 1
            if flushflag==1:
                # print(self.buff_fin_port)
                # print(self.buff_alltcp_port)
                # print(self.buff_tcp_port)
                # print(self.buff_non_port)
                if self.buff_fin_port != []:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='探测',
                        description='TCPFIN探测',
                        detail='端口有：%s'% self.buff_fin_port,
                        isdeal='端口扫描',
                        rank=1
                    )
                if self.buff_ack_port != []:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='探测',
                        description='TCPACK探测',
                        detail='端口有：%s' % self.buff_ack_port,
                        isdeal='端口扫描',
                        rank=1
                    )
                if self.buff_alltcp_port != []:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='探测',
                        description='全连接探测',
                        detail='端口有：%s' % self.buff_alltcp_port,
                        isdeal='端口扫描',
                        rank=1
                    )
                if self.buff_non_port!=[]:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='探测',
                        description='端口探测',
                        detail='端口有：%s' % self.buff_non_port,
                        isdeal='端口扫描',
                        rank=1
                    )
                if self.buff_tcp_port!=[]:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='探测',
                        description='半连接探测',
                        detail='端口有：%s' % self.buff_tcp_port,
                        isdeal='端口扫描',
                        rank=1
                    )
                if evillink!=0:
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='探测',
                        description='恶意连接',
                        detail='15秒内建立了%s条恶意连接'%str(evillink),
                        isdeal='恶意连接',
                        rank=0
                    )
                self.buff_tcp_port.clear()
                self.buff_non_port.clear()
                self.buff_alltcp_port.clear()
                self.buff_ack_port.clear()
                self.buff_fin_port.clear()
                buffer.clear()

        if data['TCP']['flags'] == 'S' and data['TCP']['sport'] == data['TCP']['dport'] and data['src'] == data['dst']:
            resdata = self._makeresdata(
                resdata=resdata,
                type='入侵',
                description='Land回路攻击',
                isdeal='Land回路攻击',
                rank=1
            )
        return resdata

    def _HTTPDETECT(self, data):
        # print('httpdetect')

        resdata = []
        srcordst = 'src' if data['src'] != IPADDRESS else 'dst'
        hacker_ip = data[srcordst]
        hacker_port=data['TCP']['dport'] if srcordst=='src' else data['TCP']['sport']
        proto = 'HTTP'
        time = data['time']
        # print(data['summary'])
        buffer = self._buffer_faillog_init(ip=hacker_ip, proto=proto)

        bru_time = 0.3 #30 seconds
        bru_count = 5 # 5 times


        if 'Raw' in data.keys():
            rawload = data['Raw']['load'].decode('utf-8', 'ignore')
            print(rawload[:30])
            web_patternu = compile(r'((txtUid|username|user|name)=(.*?))&', I)
            web_patternp = compile(r'((txtPwd|password|pwd|passwd)=(.*?))&', I)

            request_data_pat = compile(r'([GET|POST].*)\r\n', I)
            post_data_pat = compile(r'\r\n\r\n(.*)', I)
            http_response_pat = compile(r'(HTTP/1.1.*)\r\n', I)

            # HTTP get/post
            tmp_request_data=request_data_pat.findall(rawload)
            response_data=http_response_pat.findall(rawload)
            if tmp_request_data==[]:
                tmp_request_data==''
            else:
                tmp_request_data=tmp_request_data[0]
            if response_data==[]:
                response_data=''
            else:
                response_data=response_data[0]
            request_data=''
            if 'GET' in tmp_request_data or 'POST' in tmp_request_data:
                if 'GET' in tmp_request_data:
                    request_data+=str(unquote(tmp_request_data)).replace('+',' ')
                elif 'POST' in tmp_request_data:
                    request_data+=tmp_request_data
                    request_data+='; post-data:'
                    request_data+=post_data_pat.findall(rawload)[0]
                # HTTP login
                username = web_patternu.findall(request_data)
                password = web_patternp.findall(request_data)
                if username and password:
                    buffer.append({'port':hacker_port,'action':'login','time':time,'load':None,'request_data':request_data})
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='敏感信息',
                        description='尝试登录HTTP服务器，用户名：%s，密码：%s'%(username[0][2], password[0][2]),
                        detail=request_data,
                        isdeal='尝试登录HTTP服务器',
                        rank=1
                    )
                else:
                    buffer.append({'port':hacker_port,'action':'visit','time':time,'load':None,'request_data':request_data})
            else:
                if '200' in response_data:
                    for item in buffer:
                        if hacker_port == item['port']:
                            if item['load']==None:
                                item['load']=200
                elif '404' in response_data:
                    for item in buffer:
                        if hacker_port == item['port']:
                            if item['load']==None:
                                item['load']=404
                                resdata = self._makeresdata(
                                    resdata=resdata,
                                    type='探测',
                                    description='访问HTTP服务器中不存在的资源',
                                    detail=item['request_data'],
                                    isdeal='访问HTTP服务器中不存在的资源',
                                    rank=1
                                )
                elif '302' in response_data:
                    for item in buffer:
                        if hacker_port == item['port']:
                            if item['load'] == None:
                                item['load'] = 302

            login_bru_count = 0
            dir_bru_count = 0
            tmp_buff = buffer[:]
            for item in buffer:
                if time - item['time'] > bru_time:#30 seconds
                    tmp_buff.remove(item)
                else:
                    if item['load'] == 200 and login_bru_count!=-1 and item['action']=='login':
                        login_bru_count += 1
                    elif item['load'] == 302 and item['action']=='login':
                        login_bru_count = -1
                        resdata = self._makeresdata(
                            resdata=resdata,
                            type='入侵',
                            # description='尝试登录HTTP服务器，用户名：%s，密码：%s',
                            isdeal='登录HTTP服务器成功',
                            rank=2
                        )
                    elif item['load'] == 404 and item['action']=='visit':
                        dir_bru_count += 1
            buffer = tmp_buff[:]

            if login_bru_count > bru_count:
                resdata = self._makeresdata(
                    resdata=resdata,
                    type='爆破',
                    description='尝试对HTTP服务器进行用户名密码暴力破解',
                    detail='大量HTTP 200 OK状态码',
                    isdeal='尝试对HTTP服务器进行用户名密码暴力破解',
                    rank=2
                )
            if dir_bru_count > bru_count:
                resdata = self._makeresdata(
                    resdata=resdata,
                    type='爆破',
                    description='尝试对HTTP服务器进行目录暴力破解',
                    detail='大量访问不存在资源',
                    isdeal='尝试对HTTP服务器进行目录暴力破解',
                    rank=2
                )
            # if src is myself, the html maybe include the sensitive word.
            # print(rawload)
            for pattn, attk in self.ATTACK_DICT.items():  # 特征码和攻击名称
                if pattn.upper() in request_data.upper():
                    resdata = self._makeresdata(
                        resdata=resdata,
                        type='入侵',
                        description='使用web渗透攻击%s，攻击代码为%s' % (attk, pattn),
                        detail=request_data,
                        isdeal='web渗透攻击%s' % attk,
                        rank=1
                    )
        return resdata

    def _SMTP_INFO(self, data):
        # 25 端口
        redict={'username':r'dXNlcm5hbWU6\r\n(.*?)\r\n', 'password':r'UGFzc3dvcmQ6\r\n(.*?)\r\n', 'date':r'Date:(.*?)\r\n',
                'from':r'RCPT TO:(.*?)\r\n','to':r'To:(.*?)\r\n','cc':r'Cc:(.*?)\r\nSubject','messageid':r'Message-ID:(.*?)\r\n',
                'charset':'charset="(.*?)"', 'content':r'Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------='}
        rawload = data['Raw']['load'].decode('utf-8','ignore')
        for k,v in redict.items():
            res = search(v,rawload)
            restr = res.group(1).strip()

            if res !=None:
                if self._smtpsendata[k] != 'Null':
                    self._smtpsendata['ip'] = data['src'] if data['src'] not in self._iplist else data['dst']
                    self._smtpsendata['time'] = data['time']
                    # self._smtplock.acquire()
                    # self._smtpsenq.append(self._smtpsendata)
                    # self._smtplock.release()
                    self._cleansmtpsendata()
                if k == 'username' or k == 'password':
                    self._smtpsendata[k] = b64decode(self._base64padding(restr)).decode('UTF-8')
                # elif k == 'date' or k=='from' or k=='to' or k=='cc' or k=='messageid' or k==:
                else:
                    self._smtpsendata[k] = restr
    def _IMAP_INFO(self,raw_data):
        data = raw_data.decode('UTF-8', 'ignore')
        # 各种字段正则表达式
        mailuser_pwd_p = compile(r'LOGIN(.*?)\r\n', S)
        maildate_p = compile(r'Date:(.*?)\r\n', S)
        mailfrom_p = compile(r'From:(.*?)\r\n', S)
        mailto_p = compile(r'To:(.*?)\r\n', S)
        mailcc_p = compile(r'Cc:(.*?)\r\nSubject', S)
        mailsubject_p = compile(r'Subject:(.*?)\r\n', S)
        mailmessageid_p = compile(r'Message-ID:(.*?)\r\n', S)
        charset_p = compile(r'charset="(.*?)"', S)
        mailcontent_p = compile(r'Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=', S)

        username_pwd_ = mailuser_pwd_p.search(data)
        maildate_ = maildate_p.findall(data)
        mailfrom_ = mailfrom_p.findall(data)
        mailto_ = mailto_p.findall(data)
        mailcc_ = mailcc_p.search(data)
        mailsubject_ = mailsubject_p.findall(data)
        mailmessageid_ = mailmessageid_p.search(data)
        charset_ = charset_p.search(data)
        mailcontent_ = mailcontent_p.search(data)
        charset = charset_.group(1) if charset_ else 'UTF-8'
        username_pwd = username_pwd_.group(1).strip() if username_pwd_ else None
        if username_pwd:
            username = username_pwd.split()[0]
            password = username_pwd.split()[-1][1:-1]
        else:
            username = None
            password = None
        maildate = maildate_[-1].strip() if maildate_ else None
        mailfrom_ = mailfrom_[-1].strip() if mailfrom_ else None
        if mailfrom_ and ('=?' in mailfrom_):
            mailfrom_ = mailfrom_.split('?')
            mailfrom_address = mailfrom_[-1].split()[-1]
            mailfrom_name = b64decode(self._base64padding(mailfrom_[3])).decode(mailfrom_[1], 'ignore')
            mailfrom = "{}".format(mailfrom_name) + " " + mailfrom_address
        else:
            mailfrom = mailfrom_
        mailto_ = mailto_[-1].strip() if mailto_ else None
        if mailto_ and '=?' in mailto_:
            mailto_ = mailto_.split('?')
            mailto_address = mailto_[-1].split()[-1]
            mailto_name = b64decode(self._base64padding(mailto_[3])).decode(mailto_[1], 'ignore')
            mailto = "{}".format(mailto_name) + " " + mailto_address
        else:
            mailto = mailto_
        mailcc = mailcc_.group(1).strip() if mailcc_ else None
        mailmessageid = mailmessageid_.group(1).strip() if mailmessageid_ else None
        if mailsubject_:
            mailsubject_ = mailsubject_[-1].strip()
            if mailsubject_ and '=?' in mailsubject_:
                mailsubject_ = mailsubject_.split('?')
                mailsubject = b64decode(self._base64padding(mailsubject_[3])).decode(mailsubject_[1], 'ignore')
            else:
                mailsubject = mailsubject_
        else:
            mailsubject = None
        if mailcontent_:
            mailcontent_ = mailcontent_.group(1).strip().replace('\r\n', '')
            mailcontent = b64decode(self._base64padding(mailcontent_)).decode(charset, 'ignore')
        else:
            mailcontent = None
        attachs_dict = self._FIND_MAIL_ATTACH(raw_data)
        parse_data = {'username': username, 'password': password, 'maildate': maildate, 'mailfrom': mailfrom,
                      'mailto': mailto, 'mailcc': mailcc, 'mailsubject': mailsubject, 'mailmessageid': mailmessageid,
                      'mailcontent': mailcontent, 'attachs_dict': attachs_dict}
        return parse_data
    def _POP3_INFO(self,data):
        resdata = []
        srcordst = 'src' if data['src'] != IPADDRESS else 'dst'
        ip = data[srcordst]
        proto = 'POP3'
        time = data['time']
        buffer = self._buffer_faillog_init(ip=ip, proto=proto)
        if 'Raw' in data.keys():
            rawload = data['Raw']['load'].decode('utf-8', 'ignore')
            # 各种字段正则表达式
            mailuser_p = compile(r'USER(.*?)\r\n', S)
            mailpasswd_p = compile(r'PASS(.*?)\r\n', S)
            maildate_p = compile(r'Date:(.*?)\r\n', S)
            mailfrom_p = compile(r'From:(.*?)\r\n', S)
            mailto_p = compile(r'To:(.*?)\r\n', S)
            mailcc_p = compile(r'Cc:(.*?)\r\nSubject', S)
            mailsubject_p = compile(r'Subject:(.*?)\r\n', S)
            mailmessageid_p = compile(r'Message-ID:(.*?)\r\n', S)
            charset_p = compile(r'charset="(.*?)"', S)
            mailcontent_p = compile(r'Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=',S)

            username_ = mailuser_p.search(data)
            password_ = mailpasswd_p.search(data)
            maildate_ = maildate_p.findall(data)
            mailfrom_ = mailfrom_p.findall(data)
            mailto_ = mailto_p.findall(data)
            mailcc_ = mailcc_p.search(data)
            mailsubject_ = mailsubject_p.findall(data)
            mailmessageid_ = mailmessageid_p.search(data)
            charset_ = charset_p.search(data)
            mailcontent_ = mailcontent_p.search(data)
            charset = charset_.group(1) if charset_ else 'UTF-8'
            username = username_.group(1).strip() if username_ else None
            password = password_.group(1).strip() if password_ else None
            maildate = maildate_[-1].strip() if maildate_ else None
            mailfrom_ = mailfrom_[-1].strip() if mailfrom_ else None

            if mailfrom_ and '=?' in mailfrom_:
                mailfrom_ = mailfrom_.split('?')
                mailfrom_address = mailfrom_[-1].split()[-1]
                mailfrom_name = b64decode(self._base64padding(mailfrom_[3])).decode(mailfrom_[1], 'ignore')
                mailfrom = "{}".format(mailfrom_name) + " " + mailfrom_address
            else:
                mailfrom = mailfrom_
            mailto_ = mailto_[-1].strip() if mailto_ else None
            if mailto_ and '=?' in mailto_:
                mailto_ = mailto_.split('?')
                mailto_address = mailto_[-1].split()[-1]
                mailto_name = b64decode(self._base64padding(mailto_[3])).decode(mailto_[1], 'ignore')
                mailto = "{}".format(mailto_name) + " " + mailto_address
            else:
                mailto = mailto_
            mailcc = mailcc_.group(1).strip() if mailcc_ else None
            mailmessageid = mailmessageid_.group(1).strip() if mailmessageid_ else None
            if mailsubject_:
                mailsubject_ = mailsubject_[-1].strip()
                if mailsubject_ and '=?' in mailsubject_:
                    mailsubject_ = mailsubject_.split('?')
                    mailsubject = b64decode(self._base64padding(mailsubject_[3])).decode(mailsubject_[1], 'ignore')
                else:
                    mailsubject = mailsubject_
            else:
                mailsubject = None
            if mailcontent_:
                mailcontent_ = mailcontent_.group(1).strip().replace('\r\n', '')
                mailcontent = b64decode(self._base64padding(mailcontent_)).decode(charset, 'ignore')
            else:
                mailcontent = None
            attachs_dict = self._FIND_MAIL_ATTACH(rawload)
            parse_data = {'username': username, 'password': password, 'maildate': maildate, 'mailfrom': mailfrom,
                          'mailto': mailto, 'mailcc': mailcc, 'mailsubject': mailsubject, 'mailmessageid': mailmessageid,
                          'mailcontent': mailcontent, 'attachs_dict': attachs_dict}
    def _FIND_MAIL_ATTACH(self,raw_data):
        # 寻找mail中的所有附件
        filename_p = compile(r'filename="(.*?)"', S)
        attachs_dict = dict()
        charset = 'UTF-8'
        data_list = raw_data.decode('UTF-8', 'ignore').split('\r\n\r\n')
        switch = False
        for data in data_list:
            if switch:
                if data:
                    data = data.strip().replace('\r\n', '')
                    filedata = b64decode(self._base64padding(data))
                else:
                    filedata = None
                try:
                    filedata = filedata.decode(charset)
                except Exception as e:
                    pass
                attachs_dict[filename] = filedata
                switch = False
            if 'filename' in data:
                switch = True
                filename_ = filename_p.search(data)
                if filename_:
                    filename_ = filename_.group(1).strip()
                    if filename_ and '=?' in filename_:
                        filename_ = filename_.split('?')
                        charset = filename_[1]
                        filename = b64decode(self._base64padding(filename_[3])).decode(charset, 'ignore')
                    else:
                        filename = filename_
                else:
                    filename = 'unknown'
        return attachs_dict



    def _data_extract(self):
        pass
    def _base64padding(self, data):
        missing_padding = 4 - len(data) % 4
        if missing_padding:
            data += '=' * missing_padding
        return data

    def _bytestostr(self,b):
        buff = BytesIO(b)
        f = gzip.GzipFile(fileobj=buff)
        b = f.read().decode('utf-8')
        return b


            