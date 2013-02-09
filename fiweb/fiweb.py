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

from classObjects import fiWeb
from classObjects import fiWebParser
from classObjects import fiWebTemplate
from classObjects import Vulnerability
from emailTemplates import emailFunctions

started = int(time.time())
TEST = True

URL_BASE        = 'https://www.finnean.com/fiweb'
SCAN_HOME       = '/var/www/sdocs/finnean.com/fiweb'
if TEST:
    URL_BASE        = 'https://test.finnean.com/fiweb'
    SCAN_HOME       = '/var/www/sdocs/test.finnean.com/fiweb'

W3AF            = '/usr/local/w3af/w3af_console'
FIWEB_PATH      = '/usr/local/fisuite/fiweb'
TMPDIR          = '/usr/local/fisuite/tmp/fiweb-cache'

os.chdir(FIWEB_PATH)

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

# ---------------------------------------------------------
# get the next user in the queue
user = fquery.select(query="""SELECT * FROM fi_web WHERE completed='N' ORDER BY id""")
if not user: sys.exit(0)

fiweb = fiWeb.fiWeb()
mapper = DictionaryToAttributeMapper.DictionaryToAttributeMapper()
mapper.map(user[0], fiweb)

# ---------------------------------------------------------
# did the user add the fibasic.txt file to the root directory?
#u = urlparse.urlparse(fibasic.hostname)
#url = '://'.join([u[0], u[1]])
#
#if url.endswith('/'):
#    url += 'fibasic.txt'
#else:
#    url += '/fibasic.txt'
#
#txtfile = None
#try:
#    txtfile = urllib2.urlopen(url)
#except urllib2.HTTPError:
#    emailFunctions.fileNotFound(fibasic.email, fibasic.hostname)
#    print 'file not found'
#    sys.exit(0)
#
#fout = txtfile.read()
#if fibasic.file_contents not in fout:
#    emailFunctions.keyMismatch(fibasic.email, fibasic.hostname)
#    print 'key mismatch'
#    sys.exit(0)

# ---------------------------------------------------------
# is the scanner already running? If yes, then quit and wait
running = fquery.select(query="""SELECT running FROM fi_web_status WHERE id=1""")
if running[0]['running'] == 'Y':
    sys.exit(0)
else:
    fquery.select(query="""UPDATE fi_web_status SET running='Y' WHERE id=1""")

# ---------------------------------------------------------
# generate the fibasic command template
f = '-'.join([str(fiweb.account_id), str(started)])
w3af_file = '.'.join([f, 'w3af'])
fname = '/'.join([TMPDIR, w3af_file])
fd = open(fname, 'w')
s = fiWebTemplate.s % (TMPDIR, f, fiweb.url)
fd.write(s)
fd.close()

print f
print fiweb.url

# run the scan command
process_args = [W3AF, '-s', fname]
subprocess.call(process_args)
# ---------------------------------------------------------
# parse the results
parser = fiWebParser.fiWebParser()

parser.setFilename(TMPDIR + '/' + f + '.xml')
parser.parse()

high = parser.getHigh()
medium = parser.getMedium()
low = parser.getLow()

H = len(high)
M = len(medium)
L = len(low)

# ---------------------------------------------------------
# CSV file (for spreadsheet)
csv_file = '%s.txt' % f
fd = open('/'.join([TMPDIR, csv_file]), 'w')

if len(high) > 0:
    for h in high:
        s = "%s|%s|%s|%s\n" % ('HIGH', h['name'], h['url'], h['description'])
        fd.write(s)

if len(medium) > 0:
    for m in medium:
        s = "%s|%s|%s|%s\n" % ('MEDIUM', m['name'], m['url'], m['description'])
        fd.write(s)

if len(low) > 0:
    for l in low:
        s = "%s|%s|%s|%s\n" % ('LOW', l['name'], l['url'], l['description'])
        fd.write(s)
fd.close()

ended = int(time.time())
# ---------------------------------------------------------
# scan complete update db flag for next scan
fquery.select(query="""UPDATE fi_web_status SET running='N' WHERE id=1""")
fquery.select(
    query="""UPDATE fi_web SET started=%s, ended=%s, completed='Y' WHERE id=%s""",
    arg_list = [
        started,
        ended,
        fiweb.id
    ]
)

# ---------------------------------------------------------
# send confirmation email
#URL = '/'.join([URL_BASE, page_file])
#emailFunctions.scanComplete(fibasic.email, fibasic.hostname, URL)

# ---------------------------------------------------------
# close all connections
fcur.close()
fdb.close()

# ---------------------------------------------------------
