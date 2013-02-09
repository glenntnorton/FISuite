#!/usr/bin/env python
# ---------------------------------------------------------
# fibasic.py
# Free Version Scanner
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

from classObjects import fiBasic
from classObjects import fiBasicParser
from classObjects import fiBasicTemplate
from classObjects import Vulnerability
from emailTemplates import emailFunctions

from Cheetah.Template import Template

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plot


start = int(time.time())

fibasic = fiBasic.fiBasic()

URL_BASE        = 'https://www.finnean.com/fibasic'
SCAN_HOME       = '/var/www/sdocs/finnean.com/fibasic'
W3AF            = '/usr/local/w3af/w3af_console'
FIBASIC_PATH    = '/usr/local/fisuite/fibasic'
HTMLDOC         = '/usr/bin/htmldoc --quiet --webpage --fontsize 8.0 --bodyfont sans'
TMPDIR          = '/usr/local/fisuite/tmp/fibasic-cache'

os.chdir(FIBASIC_PATH)

# ---------------------------------------------------------

def setLevel(num):
    CRITICAL = 10
    HIGH_CEIL = 9.9
    HIGH_FLOOR = 7.0
    MEDIUM_CEIL = 6.9
    MEDIUM_FLOOR = 4.0
    LOW_CEIL = 3.9
    LOW_FLOOR = 0.0

    num = int(num)

    if num == CRITICAL:
        return "Critical"
    elif num <= HIGH_CEIL and num >= HIGH_FLOOR:
        return "High"
    elif num <=MEDIUM_CEIL and num >= MEDIUM_FLOOR:
        return "Medium"
    elif num <= LOW_CEIL and num >= LOW_FLOOR:
        return "Low"
    else:
        return "N/A"

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
# osvdb
oconn = MySQLConnection.MySQLConnection()
odb = oconn.connect( {
    'host' : 'localhost',
    'user' : 'osvdb',
    'passwd' : 'ADie80osvdb',
    'db' : 'osvdb'
} )
if not odb: raise ValueError, 'OSVDB-COULD NOT CONNECT TO DATABASE'

ocur = MySQLDictionaryCursor.MySQLDictionaryCursor(odb).get()
oquery = MySQLQuery.MySQLQuery()
oquery.setCursor(ocur)
oquery.setExceptionHandler(odb.Error)
oquery.setQuoteHandler(odb.escape)

# ---------------------------------------------------------
# get the next user in the queue
user = fquery.select(query="""SELECT * FROM fi_basic WHERE completed='N' ORDER BY id""")
if not user: sys.exit(0)

fibasic = fiBasic.fiBasic()
mapper = DictionaryToAttributeMapper.DictionaryToAttributeMapper()
mapper.map(user[0], fibasic)

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
running = fquery.select(query="""SELECT running FROM fi_basic_status WHERE id=1""")
if running[0]['running'] == 'Y':
    sys.exit(0)
else:
    fquery.select(query="""UPDATE fi_basic_status SET running='Y' WHERE id=1""")

# ---------------------------------------------------------
# generate the fibasic command template
w3af_file = '.'.join([str(fibasic.scan_id), 'w3af'])
fname = '/'.join([TMPDIR, w3af_file])
fd = open(fname, 'w')
s = fiBasicTemplate.s % (TMPDIR, fibasic.scan_id, fibasic.hostname)
fd.write(s)
fd.close()

# run the scan command
process_args = [W3AF, '-s', fname]
subprocess.call(process_args)
# ---------------------------------------------------------
# parse the results
parser = fiBasicParser.fiBasicParser()
xml_file = '/'.join([TMPDIR, str(fibasic.scan_id)])
parser.setFilename('.'.join([xml_file, 'xml']))
parser.parse()

high = parser.getHigh()
medium = parser.getMedium()
low = parser.getLow()

H = len(high)
M = len(medium)
L = len(low)

# ---------------------------------------------------------
# create pie chart
plot.figure(figsize = (5, 5))

data = []
labels = []
explode = []
colors = []

v = (H, M, L)
l = ('High', 'Medium', 'Low')
c = ('#ff0000', '#00ff00', '#ffff00')

for i in range(0, len(v)):
    if v[i] > 0:
        data.append(v[i])
        labels.append(l[i])
        explode.append(0.02)
        colors.append(c[i])

plot.pie(data, colors = colors, explode = explode, labels = labels, autopct = None);
plot.title('Vulnerabilities', bbox = {'facecolor': '0.9', 'pad': 15})


img_file = '/'.join([SCAN_HOME, fibasic.scan_id])
plot.savefig(img_file)

# ---------------------------------------------------------
# HTML Webpage
TMPL_FILE = '/'.join([SCAN_HOME, 'fibasic-results.tmpl'])
html = Template(file=TMPL_FILE)

html.no_results = False
if len(high) == 0 and len(medium) == 0 and len(low) == 0:
    html.no_results = True
else:
    html.img = '.'.join([str(fibasic.scan_id), 'png'])

html.host = fibasic.hostname
html.high = high
html.medium = medium
html.low = low


page_file = '%s.html' % fibasic.scan_id
fd = open('/'.join([SCAN_HOME, page_file]), 'w')
fd.write(html.respond())
fd.close()

# ---------------------------------------------------------
# CSV file (for spreadsheet)
csv_file = '%s.txt' % fibasic.scan_id
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

# ---------------------------------------------------------
# scan complete update db flag for next scan
fquery.select(query="""UPDATE fi_basic_status SET running='N' WHERE id=1""")
fquery.select(
    query="""UPDATE fi_basic SET completed='Y' WHERE scan_id=%s""",
    arg_list = [fibasic.scan_id]
)

# ---------------------------------------------------------
# send confirmation email
URL = '/'.join([URL_BASE, page_file])
emailFunctions.scanComplete(fibasic.email, fibasic.hostname, URL)

# ---------------------------------------------------------
# close all connections
fcur.close()
fdb.close()

ocur.close()
odb.close()

# ---------------------------------------------------------
