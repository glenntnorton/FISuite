#!/usr/bin/env python
# ---------------------------------------------------------
# fiweb.py
# Full Audit Version Scanner
# Finnean-SSC
# www.finnean.com
# ---------------------------------------------------------

import os
os.environ['MPLCONFIGDIR'] = '/tmp'
os.environ['HTMLDOC_NOCGI'] = '1'

import re
import smtplib
import subprocess
import sys
import time
import urllib2
import urlparse

from com.finnean.database.connection import MySQLConnection
from com.finnean.database.cursor import MySQLDictionaryCursor
from com.finnean.database.query  import MySQLQuery
from com.finnean.object.map import DictionaryToAttributeMapper

from classObjects import fiNetwork
from emailTemplates import emailFunctions

started = int(time.time())

FINETWORK_PATH  = '/usr/local/fisuite/finetwork'
TMPDIR          = '/usr/local/fisuite/tmp/finetwork-cache'
os.chdir(FINETWORK_PATH)

# ---------------------------------------------------------
# DB Connections
# finnean.com
fconn = MySQLConnection.MySQLConnection()
fdb = fconn.connect( {
    'host' : 'localhost',
    'user' : 'fssc',
    'passwd' : 'ADie80fssc',
    'db' : 'finnean.com'
} )
if not fdb: raise ValueError, 'FINNEAN.COM - COULD NOT CONNECT TO DATABASE'

fcur = MySQLDictionaryCursor.MySQLDictionaryCursor(fdb).get()
fquery = MySQLQuery.MySQLQuery()
fquery.setCursor(fcur)
fquery.setExceptionHandler(fdb.Error)
fquery.setQuoteHandler(fdb.escape)

finetwork = fiNetwork.fiNetwork()
# ---------------------------------------------------------
# get the next user in the queue
user = fquery.select(query="""SELECT * FROM fi_network WHERE completed='N' ORDER BY id""")
if not user: sys.exit(0)

fiweb = fiNetwork.fiNetwork()
mapper = DictionaryToAttributeMapper.DictionaryToAttributeMapper()
mapper.map(user[0], finetwork)

# ---------------------------------------------------------
# is the scanner already running? If yes, then quit and wait
running = fquery.select(query="""SELECT running FROM fi_network_status WHERE id=1""")
if running[0]['running'] == 'Y':
    sys.exit(0)
else:
    fquery.select(query="""UPDATE fi_network_status SET running='Y' WHERE id=1""")

# ---------------------------------------------------------
# create the target file
target_file = '-'.join(['ACCT', str(finetwork.account_id), str(started)])
nbe_file = target_file + '.nbe'
target_file += '.txt'

tfile = '/'.join([TMPDIR, target_file])
fd = open(tfile, 'w')
fd.write(str(finetwork.ip))
fd.close()

# ---------------------------------------------------------
# run the process
_exe = '/usr/bin/OpenVAS-Client'
_rc = sys.argv[1]
_h = 'localhost'
_p = '9390'
_u = 'openvas'
_pp = 'ADie80openvas'
_t = '/'.join([TMPDIR, target_file])
_o = '/'.join([TMPDIR, nbe_file])
process_args = [_exe, '-c', _rc, '-T', 'nbe', '-q', _h, _p, _u, _pp, _t, _o]
process = subprocess.Popen(process_args, shell=False, stdout=subprocess.PIPE)
o, e = process.communicate()

import pprint
try:
    pprint.pprint(o)
except StandardError:
    pass
try:
    pprint.pprint(e)
except StandardError:
    pass

# ---------------------------------------------------------
# scan complete update db flag for next scan
ended = int(time.time())

fquery.select(query="""UPDATE fi_network_status SET running='N' WHERE id=1""")
fquery.select(
    query="""UPDATE fi_network SET started=%s, ended=%s, completed='Y' WHERE id=%s""",
    arg_list = [
        started,
        ended,
        finetwork.id
    ]
)

# ---------------------------------------------------------
# close all connections
fcur.close()
fdb.close()

# ---------------------------------------------------------
