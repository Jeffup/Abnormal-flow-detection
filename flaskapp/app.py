# -*- coding: utf-8 -*-
# tips:
import os

from flask import Flask, render_template, jsonify, request,copy_current_request_context
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, func,event,or_ ,and_, desc# text用与order_by转换文本，func用于group_by统计
from flask_socketio import SocketIO,send,emit
from threading import Lock
from datetime import datetime, time
from time import sleep,strftime,localtime


# 自己写的文件
from functions.mysqlctl import create_session, EVENT_COUNT,EVENT_ALARM,IP_COUNT
from functions.getcominfo import bytes2human, ComInfo
# from templates.pytemplates.forms import SearchEventForm
# from functions.sniffer import Sniffer
# from functions.pktanalysis import PacketAnalysis
from config import *

# 尤其需要注意添加static与templates的路径
app = Flask(import_name=__name__,static_folder='static', template_folder='templates')

app.debug=True
app.config['SECRET_KEY']=SECRET_KEY
app.config["SQLALCHEMY_ECHO"] = False

BUFFER_NEW_MSG=[]
BUFFER_TIME=[]

THREAD_ALARMSENT=None
THREAD_COMINFOSENT=None

THREAD_LOCK = Lock()
BUFFER_LOCK = Lock()

# 创建websocketio双工实时同步信息
async_mode = None
socketio = SocketIO(app , cors_allowed_origins="*")
SOCKET_NAMESPACE = '/capture'
# VIEW
TEMP_LIDATA=[{'action':'','web':'index','name':'首页'},
        # {'action':'','web':'ips','name':'IP查询'},
        {'action':'','web':'events','name':'事件查询'},
        {'action':'','web':'config','name':'设置'}]

@app.route('/')
@app.route('/index')
def root():
    lidata=TEMP_LIDATA
    lidata[0]['action']='action'
    return render_template('index.html',lidata=lidata)

@app.route('/ipdetail',methods=['POST', 'GET'])
def ipdetail():
    lidata=TEMP_LIDATA
    lidata[1]['action']='action'
    queryip=request.args.get('ip',str)
    return render_template('ipdetail.html',ip=queryip, lidata=lidata)

@app.route('/events',methods=['POST', 'GET'])
def events():
    lidata=TEMP_LIDATA
    lidata[2]['action']='action'
    options=['入侵','爆破','敏感信息','探测']
    return render_template('events.html',options=options, lidata=lidata)

# CONTROL
@app.route('/querydata/<any(events,ipdetail,alarm):type>',methods=['POST', 'GET'])
def querydata(type):
    if type=='ipdetail':
        pageSize = request.args.get('rows')
        pageIndex = request.args.get('page')
        pageOrderType = request.args.get('sortOrder', str)
        pageOrderCol = request.args.get('sort', str)

        session = create_session()

        queryIp = request.args.get('queryip',str)
        page=session.query(EVENT_COUNT).filter(EVENT_COUNT.ip==queryIp)

        total=page.count()
        page=page.order_by(text(pageOrderCol+' '+pageOrderType)).\
            slice((int(pageIndex) - 1) * int(pageSize), int(pageIndex) * int(pageSize))
        # page=EVENT_COUNT.query.filter(EVENT_COUNT.ip==queryIp).order_by(text(pageOrderCol+' '+pageOrderType)).paginate(int(pageIndex), int(pageSize),False)
        # pageItems = page.items
        data=[]
        for item in page.all():
            data.append({'time':item.time.strftime("%Y-%m-%d %H:%M:%S"),'attacktype':item.type,'description':item.description,'detail':item.detail})

        # 统计数据填补
        statisticip = session.query(IP_COUNT).filter(IP_COUNT.ip == queryIp).first()
        # statisticip = IP_COUNT.query.filter(IP_COUNT.ip==queryIp).first()
        statistictype = session.query(EVENT_COUNT.type, func.count('*').label('typecount')).filter(
            EVENT_COUNT.ip == queryIp).group_by(EVENT_COUNT.type).all()
        # statistictype =EVENT_COUNT.query.with_entities(EVENT_COUNT.type, func.count('*').label('typecount')).filter( EVENT_COUNT.ip==queryIp).group_by( EVENT_COUNT.type).all()
        statistic = [{'mac':statisticip.mac,'first_time':statisticip.first_time.strftime("%Y-%m-%d %H:%M:%S"),'last_time':statisticip.last_time.strftime("%Y-%m-%d %H:%M:%S"),'attack_count':statisticip.attack_count},{}]
        # print(statistic)
        for item in statistictype:
            statistic[1][item[0]]=item[1]
        session.close()
        return jsonify({'total': total, 'rows': data, 'statistic':statistic})
    elif type=='events':
        pageSize = request.args.get('rows')
        pageIndex = request.args.get('page')
        pageOrderType = request.args.get('sortOrder', str)
        pageOrderCol = request.args.get('sort', str)

        session = create_session()
        page = session.query(EVENT_COUNT)
        order_by_total = func.count('*').label('total')
        ipcount=session.query(EVENT_COUNT.ip,order_by_total)
        protocolcount = session.query(EVENT_COUNT.protocol, order_by_total)
        flowcount=session.query(func.sum(EVENT_COUNT.length))
        # page = EVENT_COUNT.query
        attacktype=request.args.getlist('attacktype[]') #*****
        startdate= request.args.get('startdate',str)# func.from_unixtime((Table.timestamp), "%Y-%m-%d %H:%i:%s")
        enddate = request.args.get('enddate',str)
        detail = request.args.get('detail')

        if attacktype!=[]:
            page = page.filter(EVENT_COUNT.type.in_(attacktype))
            ipcount = ipcount.filter(EVENT_COUNT.type.in_(attacktype))
            protocolcount = protocolcount.filter(EVENT_COUNT.type.in_(attacktype))
            flowcount = flowcount.filter(EVENT_COUNT.type.in_(attacktype))
            # for type in attacktype:
            #     page = page.filter(EVENT_COUNT.type==type)
            #     ipcount = ipcount.filter(EVENT_COUNT.type == type)
            #     protocolcount=protocolcount.filter(EVENT_COUNT.type==type)
            #     flowcount=flowcount.filter(EVENT_COUNT.type == type)
        if startdate!="":
            page=page.filter(EVENT_COUNT.time>=startdate)
            ipcount = ipcount.filter(EVENT_COUNT.time>=startdate)
            protocolcount = protocolcount.filter(EVENT_COUNT.time>=startdate)
            flowcount=flowcount.filter(EVENT_COUNT.time>=startdate)
        if enddate!="":
            page = page.filter(EVENT_COUNT.time <=enddate)
            ipcount = ipcount.filter(EVENT_COUNT.time <=enddate)
            protocolcount = protocolcount.filter(EVENT_COUNT.time <=enddate)
            flowcount=flowcount.filter(EVENT_COUNT.time <=enddate)
        if detail!="":
            detail='%'+detail+'%'
            page = page.filter(or_(EVENT_COUNT.detail.like(detail),EVENT_COUNT.description.like(detail),EVENT_COUNT.ip.like(detail)))
            ipcount = ipcount.filter(or_(EVENT_COUNT.detail.like(detail),EVENT_COUNT.description.like(detail),EVENT_COUNT.ip.like(detail)))
            protocolcount = protocolcount.filter(or_(EVENT_COUNT.detail.like(detail),EVENT_COUNT.description.like(detail),EVENT_COUNT.ip.like(detail)))
            flowcount=flowcount.filter(or_(EVENT_COUNT.detail.like(detail),EVENT_COUNT.description.like(detail),EVENT_COUNT.ip.like(detail)))

        attackcount=page.count()
        flowcount=bytes2human(flowcount.scalar()) if flowcount.scalar()!=None else 0
        sendatacount=page.filter(or_(EVENT_COUNT.description.like('%敏感%'), EVENT_COUNT.description.like('%上传下载%'))).count()
        # print(sendatacount)
        ipcount_num = ipcount.group_by(EVENT_COUNT.ip).count()
        ipcount_10 = ipcount.group_by(EVENT_COUNT.ip).order_by(desc(order_by_total)).limit(10).all()
        protocolcount_10 = protocolcount.group_by(EVENT_COUNT.protocol).order_by(desc(order_by_total)).limit(10).all()

        # group_by(EVENT_COUNT.protocol).order_by(desc(order_by_total)).limit(10).all()
        # page= page.order_by(text(str(pageOrderCol) + ' ' + str(pageOrderType))).paginate(int(pageIndex),int(pageSize), False)
        page= page.order_by(text(str(pageOrderCol) + ' ' + str(pageOrderType))).slice((int(pageIndex) - 1) * int(pageSize), int(pageIndex) * int(pageSize))
        # pageItems = page.items
        data = []
        for item in page.all():
            ipinfo = session.query(IP_COUNT).filter(IP_COUNT.ip == item.ip).first()
            # ipinfo=IP_COUNT.query.filter(IP_COUNT.ip==item.ip).first()
            data.append({'ip': item.ip, 'first_time':ipinfo.first_time.strftime("%Y-%m-%d %H:%M:%S"), 'last_time': ipinfo.last_time.strftime("%Y-%m-%d %H:%M:%S"), 'attacktype': item.type,'protocol':item.protocol,
                         'length':item.length,'time':item.time, 'description': item.description,'detail': item.detail})
        attackipdata={}
        protocoldata={}
        for item in ipcount_10:
            attackipdata[item.ip]=item.total
        for item in protocolcount_10:
            protocoldata[item.protocol]=item.total
        session.close()
        # print(dir(page))
        # return jsonify({'total': page.total, 'rows': data})
        return jsonify({'total': attackcount, 'rows': data, 'attackcount':attackcount,'flowcount':flowcount,'ipcount':ipcount_num,'sendatacount':sendatacount,
                        'attackipdata':attackipdata,'protocoldata':protocoldata})
    elif type=='alarm':
        pageOrderType = request.args.get('sortOrder', str)
        pageOrderCol = request.args.get('sort', str)

        session = create_session()
        page = session.query(EVENT_ALARM).filter(EVENT_ALARM.isdeal=='wait')
        total = page.count()

        # page= page.order_by(text(str(pageOrderCol) + ' ' + str(pageOrderType))).paginate(int(pageIndex),int(pageSize), False)
        page = page.order_by(text(str(pageOrderCol) + ' ' + str(pageOrderType)))
        # pageItems = page.items
        data = []
        for item in page.all():
            data.append({'id':item.id,'ip': item.ip, 'time': item.time.strftime("%Y-%m-%d %H:%M:%S"), 'description': item.description})
        session.close()
        # print(dir(page))
        # return jsonify({'total': page.total, 'rows': data})
        return jsonify({'total': total, 'rows': data})

# @event.listens_for(EVENT_ALARM, 'after_insert')
# @event.listens_for(EVENT_ALARM, 'after_update')
# def alarmevent(mapper, connection, target):
#     # print('yes')
#     if target.isdeal!='ok':
#         resdata={}
#         resdata['id']=target.id
#         resdata['ip']=target.ip
#         resdata['time']=target.time
#         resdata['description']=target.description
#         # LOCK!
#         # Will lock wait for a long time while the other thread is running?
#         BUFFER_LOCK.acquire()
#         BUFFER_NEW_MSG.append(resdata)
#         print(BUFFER_NEW_MSG)
#         BUFFER_LOCK.release()

@socketio.on('connect', namespace=SOCKET_NAMESPACE)
def test():
    @copy_current_request_context
    def cominfosent():
        cominfo = ComInfo()
        olddata = cominfo.get_netinfo()
        while True:
            date = strftime("%Y-%m-%d %H:%M:%S", localtime())
            # if BUFFER_TIME!=[] and BUFFER_TIME[0]
            cpuinfo = cominfo.get_cpuinfo()
            meminfo = cominfo.get_meminfo()
            diskinfo = cominfo.get_diskinfo()
            netinfo = cominfo.get_netinfo()
            resdata = {'in_speed': [date, bytes2human((netinfo['bytes_sent'] - olddata['bytes_sent']) / 2 if (
                        netinfo['bytes_sent'] - olddata['bytes_sent'] > 0) else 0, mode=2)['value']],
                       'out_speed': [date, bytes2human((netinfo['bytes_recv'] - olddata['bytes_recv']) / 2 if (
                        netinfo['bytes_recv'] - olddata['bytes_recv'] > 0) else 0, mode=2)['value']]
                       }
            olddata = netinfo
            resdata.update(cpuinfo)
            resdata.update(meminfo)
            resdata.update(diskinfo)
            # print(resdata)
            emit('com_infomation', resdata)
            sleep(2)
    @copy_current_request_context
    def alarmsent():
        idlist = []
        resdata = []
        while True:
            # print('1234567891616518651865')
            resdata.clear()
            idlist.clear()
            with open("./tmpfile/alarmbuffer", 'r+') as fout:
                for item in fout.readlines():
                    idlist.append(int(item.strip('\n')))
            with open("./tmpfile/alarmbuffer", 'w') as fin:
                fin.truncate()
            # print(idlist)
            if idlist!=[]:
                print(idlist)
                session=create_session()
                for id in idlist:
                    querydata=session.query(EVENT_ALARM).filter(EVENT_ALARM.id==id).first()#querydata.time.strftime("%Y-%m-%d %H:%M:%S")
                    resdata.append({'id':querydata.id,'ip':querydata.ip,'time':querydata.time.strftime("%Y-%m-%d %H:%M:%S"),'description':querydata.description})
                emit('new_message',{'resdata':resdata})
            sleep(1)
    global THREAD_ALARMSENT
    global THREAD_COMINFOSENT
    mindate = strftime("%Y-%m-%d %H:%M:%S", localtime())
    maxdate = strftime('%Y-%m-%d', localtime())
    maxdate += ' 23:59:59'
    resdate=[[mindate, -1],[maxdate, -1]]
    with THREAD_LOCK:
        if THREAD_COMINFOSENT is None:
            THREAD_COMINFOSENT = socketio.start_background_task(cominfosent)
        if THREAD_ALARMSENT is None:
            THREAD_ALARMSENT = socketio.start_background_task(alarmsent)
    emit('computer_msg', {'data': 'Connected', 'time': resdate})

@app.route('/dealalarm',methods=['POST'])
def dealalarm():
    id=request.form.get('id',int)
    dealtime=request.form.get('dealtime')
    session=create_session()
    dealevent = session.query(EVENT_ALARM).filter(EVENT_ALARM.id==id).first()
    dealevent.dealtime = dealtime
    dealevent.isdeal='ok'
    session.commit()
    return jsonify({'id':id})

def alarmsent():
    while True:
        if len(BUFFER_NEW_MSG)>0:
            BUFFER_LOCK.acquire()
            for item in BUFFER_NEW_MSG:
                emit('new_message',item,SOCKET_NAMESPACE)
            BUFFER_LOCK.release()
# @app.route('/getcominfo',methods=['GET'])


if __name__=='__main__':
    # pktdetect = PacketAnalysis()
    # # pktdetect.testmysql()
    # # ***************sniffer
    # sniff = Sniffer()
    # sniff.run(pktdetect.pktdecode, iface=INTERFACE)
    socketio.run(app)