# -*- coding: utf-8 -*-
# tips:
from functions.sniffer import Sniffer
from functions.mysqlctl import EVENT_ALARM
from functions.pktanalysis import PacketAnalysis
from config import *
# from app import socketio, app
from sqlalchemy import event

# ***************decode class
pktdetect = PacketAnalysis()
# pktdetect.testmysql()
@event.listens_for(EVENT_ALARM, 'after_insert')
@event.listens_for(EVENT_ALARM, 'after_update')
def alarmevent(mapper, connection, target):
    # print('yes')
    if target.isdeal!='ok':
        # resdata={}
        # resdata['id']=target.id
        # resdata['ip']=target.ip
        # resdata['time']=target.time
        # resdata['description']=target.description
        # LOCK!
        # Will lock wait for a long time while the other thread is running?
        print(target.id)
        with open("./tmpfile/alarmbuffer",'a+') as fin:
            fin.write(str(target.id)+'\r\n')


# ***************sniffer
sniff=Sniffer()
sniff.run(pktdetect.prnforsniff,iface=INTERFACE)

#  # db.drop_all()
#
#     db.create_all()
