# tips:
import os
DB_USERNAME='flaskapp'
DB_PASSWORD='hjfhjf66'
DB_NAME='db_flaskapp'
DB_URI_F='mysql://'+DB_USERNAME+':'+DB_PASSWORD+'@localhost/'+DB_NAME
DB_URI = 'mysql+pymysql://'+DB_USERNAME+':'+DB_PASSWORD+'@localhost/'+DB_NAME
"mysql+pymysql://root:123456@localhost/test"
SECRET_KEY=os.urandom(16) # auto generate secret key, '16' is seed

INTERFACE='ens33'
IPADDRESS='10.10.10.200'

DOWNLOAD_FOLDER='tmpfile'