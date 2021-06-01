# -*- coding: utf-8 -*-
# tips:
from re import *
from urllib.parse import quote, unquote
from datetime import *
from time import *
pattern =compile(r'([0-9a-zA-Z])\1{15}',I)
requestdatapat = compile(r'([GET|POST].*)\r\n',I)
postdatapat=compile(r'\r\n\r\n(.*)',I)
httpresponsepat=compile(r'(HTTP/1.1.*)\r\n',I)
get1='GET /dvwa/security.php HTTP/1.1\r\n'
get2='GET /dvwa/vulnerabilities/sqli/?id=%3Cscript%3E+s+%27+123&Submit=Submit HTTP/1.1\r\n'
http1= 'HTTP/1.1 200 OK\r\n'
http2='HTTP/1.1 404 Not Found\r\n'
http3='HTTP/1.1 302 Found\r\n'
reference='Referer: http://10.10.10.200/dvwa/vulnerabilities/sqli/?id=sdf&Submit=Submit&user_token=de986f8a94106204d8a3446356a34bcb\r\n'

post='''
POST /dvwa/login.php HTTP/1.1\r\nHost: 10.10.10.200\r\nUser-Agent: Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://10.10.10.200/dvwa/login.php\r\nCookie: security=impossible; PHPSESSID=59068ba0205a91ebd3f291fefe271d3c\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 88\r\n\r\nusername=admin&password=password&Login=Login&user_token=63604d7a9cc3f48a19b39acedfae80ff
'''

# relist1=requestdatapat.findall(http2)
# relist2=str(unquote(getpat.findall(get2)[0])).replace('+',' ')
# print(relist1)

# date = strftime("%Y-%m-%d", time())
# idlist=[]
# with open("../tmpfile/alarmbuffer", 'r+') as fout:
#     for item in fout.readlines():
#         idlist.append(int(item.strip('\n')))
# print(idlist)
print(time())


