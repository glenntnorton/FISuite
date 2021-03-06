#!/usr/bin/env python
# ---------------------------------------------------------
# forxf.py
# Fssc-ForX Free Version Scanner
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

from com.finnean.database.connection import MySQLConnection
from com.finnean.database.cursor import MySQLDictionaryCursor
from com.finnean.database.query  import MySQLQuery
from com.finnean.object.map import DictionaryToAttributeMapper
from com.finnean.web.site import Queue

import Vulnerability
import ForxfParser
import ForxfTemplate

from Cheetah.Template import Template

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plot

start = int(time.time())

queue = Queue.Queue()

URL_BASE = r'https://www.finnean.com/forxf/scans'
SCAN_HOME = r'/var/www/sdocs/finnean.com/forxf/scans'
W3AF = r'/usr/local/w3af/w3af_console'
FORXF_PATH = r'/usr/local/fssc/forxf'
HTMLDOC = '/usr/bin/htmldoc --quiet --webpage --fontsize 8.0 --bodyfont sans'
TMPDIR = r'/tmp/forxf-tmp'
os.chdir(FORXF_PATH)
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
fconn = MySQLConnection.MySQLConnection()
fdb = fconn.connect( {
    'host' : 'localhost',
    'user' : 'forxf',
    'passwd' : 'ADie80forxf',
    'db' : 'forx_free'
} )
if not fdb: raise ValueError, 'FORXF-COULD NOT CONNECT TO DATABASE'

fcur = MySQLDictionaryCursor.MySQLDictionaryCursor(fdb).get()
fquery = MySQLQuery.MySQLQuery()
fquery.setCursor(fcur)
fquery.setExceptionHandler(fdb.Error)
fquery.setQuoteHandler(fdb.escape)


# ---------------------------------------------------------

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
user = fquery.select(query="""SELECT * FROM queue WHERE completed='N' ORDER BY id""")
if not user: sys.exit(0)

queue = Queue.Queue()
mapper = DictionaryToAttributeMapper.DictionaryToAttributeMapper()
mapper.map(user[0], queue)

# ---------------------------------------------------------

# is the scanner already running? If yes, then quit and wait

running = fquery.select(query="""SELECT running FROM status WHERE id=1""")
if running[0]['running'] == 'Y':
    sys.exit(0)
else:
    fquery.select(query="""UPDATE status SET running='Y' WHERE id=1""")

# ---------------------------------------------------------

# generate the Forxf Template
w3af_file = '.'.join([str(queue.scan_id), 'w3af'])
fname = '/'.join([TMPDIR, w3af_file])
fd = open(fname, 'w')
s = ForxfTemplate.s % (TMPDIR, queue.scan_id, queue.hostname)
fd.write(s)
fd.close()

process_args = [W3AF, '-s', fname]
subprocess.call(process_args)

# ---------------------------------------------------------

parser = ForxfParser.ForxfParser()

xml_file = '/'.join([TMPDIR, str(queue.scan_id)])
parser.setFilename('.'.join([xml_file, 'xml']))
parser.parse()

high = parser.getHigh()
medium = parser.getMedium()
low = parser.getLow()

H = len(high) 
M = len(medium)
L = len(low)

# ---------------------------------------------------------

# pie chart
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


img_file = SCAN_HOME + '/%s.png' % (queue.scan_id)
plot.savefig(img_file)

# ---------------------------------------------------------
# HTML Webpage
TMPL_FILE = '/'.join([SCAN_HOME, 'forxf.html'])
html = Template(file=TMPL_FILE)

html.no_results = False
if len(high) == 0 and len(medium) == 0 and len(low) == 0:
    html.no_results = True
else:
    html.img = '.'.join([str(queue.scan_id), 'png'])

html.host = queue.hostname
html.high = high
html.medium = medium
html.low = low


page_file = '%s.html' % queue.scan_id
fd = open('/'.join([SCAN_HOME, page_file]), 'w')
fd.write(html.respond())
fd.close()



# PDF
PDF_TMPL = '/'.join([SCAN_HOME, 'forxf-pdf.html'])
pdf_html = Template(file=PDF_TMPL)
pdf_html.no_results = False
if len(high) == 0 and len(medium) == 0 and len(low) == 0:
    pdf_html.no_results = True
else:
    pdf_html.img = '.'.join([str(queue.scan_id), 'png'])

pdf_html.host = queue.hostname
pdf_html.high = high
pdf_html.medium = medium
pdf_html.low = low

pdf_file = '%s-pdf.html' % queue.scan_id
fd = open('/'.join([SCAN_HOME, pdf_file]), 'w')
fd.write(pdf_html.respond())
fd.close()

cmd = '''%s %s/%s -f %s/%s.pdf''' % (HTMLDOC, SCAN_HOME, pdf_file, SCAN_HOME, str(queue.scan_id))
os.system(cmd)

# ---------------------------------------------------------

fquery.select(query="""UPDATE status SET running='N' WHERE id=1""")
fquery.select(
    query="""UPDATE queue SET completed='Y' WHERE scan_id=%s""",
    arg_list = [queue.scan_id]
)

# ---------------------------------------------------------

# send confirmation email
smtp = smtplib.SMTP('mail.finnean.com')
sender = 'no-reply@finnean.com'
recipient = queue.email
subject = 'Fssc-Forx Online Edition Scan Complete'

headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
    sender, recipient, subject
)

URL = URL_BASE + '/%s' % page_file
email_page = file('/usr/local/fssc/forxf/forxf-email.html').read()
html = email_page % URL
msg = headers + html
smtp.sendmail(sender, recipient, msg)

# ---------------------------------------------------------

smtp.close()
fcur.close()
fdb.close()
ocur.close()
odb.close()

# ---------------------------------------------------------
