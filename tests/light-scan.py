#!/usr/bin/env python
# ---------------------------------------------------------

import subprocess
import os
os.environ['MPLCONFIGDIR'] = '/tmp'
import sys
import re
import time

from com.finnean.database.connection import MySQLConnection
from com.finnean.database.cursor import MySQLDictionaryCursor
from com.finnean.database.query  import MySQLQuery
from com.finnean.object.map import DictionaryToAttributeMapper
#from com.finnean.web.cgi import CGI

#from Cheetah.Template import Template

#import matplotlib
#matplotlib.use('Agg')
#import matplotlib.pyplot as plot

import Vulnerability
start = int(time.time())
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

# DB Connection
connection = MySQLConnection.MySQLConnection()
database = connection.connect( {
    'host' : 'localhost',
    'user' : 'osvdb',
    'passwd' : 'ADie80osvdb',
    'db' : 'osvdb'
} )
if not database: raise ValueError, 'COULD NOT CONNECT TO DATABASE'

cursor = MySQLDictionaryCursor.MySQLDictionaryCursor(database).get()
query = MySQLQuery.MySQLQuery()
query.setCursor(cursor)
query.setExceptionHandler(database.Error)
query.setQuoteHandler(database.escape)

# ---------------------------------------------------------
#cgi = CGI.CGI()
CONFIG_FILE='/usr/local/nikto/nikto.conf'
NIKTO = '/usr/local/nikto/nikto.pl'
PERL = '/usr/bin/perl'
SSL = '-ssl -p 443'
HOST = 'http://localhost/'
PLUGINS = 'robots outdated auth embedded apache_expect_xss subdomain msgs tests content_search httpoptions headers dictionary'
# ---------------------------------------------------------

osvdb_pattern = re.compile('OSVDB-(\d+)')
url_pattern = re.compile('^\+\s(/\w+)\s-')
cwd = os.getcwd()
os.chdir('/usr/local/nikto')

process_args = ['perl', 'nikto.pl', '-T', 'x1', '-D', '3', '-h', HOST]
process = subprocess.Popen(process_args, shell=False, stdout=subprocess.PIPE)
o, e = process.communicate()

fd = open('/tmp/scan.out', 'w')
fd.write(o)
fd.close()

lines = o.split('\n')
vulnerabilities = []
urls = {}
for line in lines:
    osvdb_match = re.search(osvdb_pattern, line)
    if osvdb_match:
        num = osvdb_match.groups()[0]
        vulnerabilities.append(int(num))

        sp = line.split(':')
        if sp[1].startswith(' /'):
            urls[num] = sp[1]

    url_match = re.search(url_pattern, line)
    if url_match:
        print url_match.groups()

# ---------------------------------------------------------
if len(vulnerabilities) > 0:
    sql = None
    if len(vulnerabilities) == 1:
        sql = """SELECT vulnerabilities.osvdb_id AS osvdb_id,
        vulnerabilities.description AS description,
        vulnerabilities.solution AS solution,
        cvss_metrics.score AS score 
        FROM vulnerabilities 
        INNER JOIN cvss_metrics ON
        vulnerabilities.id=cvss_metrics.vulnerability_id 
        WHERE vulnerabilities.osvdb_id = %s ORDER BY cvss_metrics.score DESC""" % vulnerabilities[0]
    else:
        sql = """SELECT vulnerabilities.osvdb_id AS osvdb_id,
        vulnerabilities.description AS description,
        vulnerabilities.solution AS solution,
        cvss_metrics.score AS score 
        FROM vulnerabilities 
        INNER JOIN cvss_metrics ON
        vulnerabilities.id=cvss_metrics.vulnerability_id 
        WHERE vulnerabilities.osvdb_id IN %s ORDER BY cvss_metrics.score DESC""" % repr(tuple(vulnerabilities))
    vulnerability_objects = []
    mapper = DictionaryToAttributeMapper.DictionaryToAttributeMapper()
    results = query.select(query=sql)
    for result in results:
        vulnerability = Vulnerability.Vulnerability()
        mapper.map(result, vulnerability)
        vulnerability.level = setLevel(vulnerability.score)
        vulnerability.url = urls.get(str(vulnerability.osvdb_id), 'N/A')
        vulnerability_objects.append(vulnerability)
    

# ---------------------------------------------------------

    TOTAL = C = H = M = L = 0
    for v in vulnerability_objects:
        if 'Critical' in v.level:
            C += 1
        elif 'High' in v.level:
            H += 1
        elif 'Medium' in v.level:
            M += 1
        elif 'Low' in v.level:
            L += 1
        TOTAL += 1


# ---------------------------------------------------------
    for obj in vulnerability_objects:
        print obj.__dict__

    end = int(time.time())
    run = end - start
    print 'Took:', run

# pie chart
#    plot.figure(figsize = (8, 8))
#
#    data = []
#    labels = []
#    explode = []
#    colors = []
#
#    v = (C, H, M, L)
#    l = ('Critical', 'High', 'Medium', 'Low')
#    c = ('#ff00ff', '#ff0000', '#00ff00', '#ffff00')
#
#    for i in range(0, len(v)):
#        if v[i] > 0:
#            data.append(v[i])
#            labels.append(l[i])
#            explode.append(0.05)
#            colors.append(c[i])
#
#    plot.pie(data, colors = colors, explode = explode, labels = labels, autopct = None);
#    plot.title('Vulnerabilities', bbox = {'facecolor': '0.9', 'pad': 15})
#
#
#    filename = '/var/www/fssc/sdocs/www.finnean.com/images/scans/foo.png'
#    plot.savefig(filename)

# ---------------------------------------------------------
    cursor.close()
    database.close()

#    os.chdir(cwd)
#    html = Template(file='../scan-results.html')
#    html.vulnerabilities = vulnerability_objects
#    html.no_results = False
#    html.host = HOST

#    print "Content-type: text/html\n"
#    print html
else:
    cursor.close()
    database.close()

#    os.chdir(cwd)
#    html = Template(file='../scan-results.html')
#    html.no_results = True
#    html.host = HOST

#    print "Content-type: text/html\n"
#    print html
# ---------------------------------------------------------
