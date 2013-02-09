#!/usr/bin/env python

# trying to parse the openvas nbe results
# open the file and read all

import os
os.environ['MPLCONFIGDIR'] = '/tmp'
import re
import smtplib
import subprocess
import sys
import time

from Cheetah.Template import Template

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plot

# ---------------------------------------------------------

DOTS     = re.compile('( \.|\.\. )')
FIX      = re.compile('(10180|10287|10330|10386|10662|10761|10863|10919|'
                        +'11011|11033|11153|11936|12053|12245|12634|14773|'
                        +'17975|18261|18528|19506|22964|'
                        +'11040|11822|11865|14674)\\|(1|2|3)')
GMT      = re.compile('GMT(\!|\.)')
PIPE     = re.compile('[ ]*\\|[ ]*')
SOLUTION = re.compile('(Solution:|Risk factor:|CVSS|Plugin output:|See also:|'
                        +'CVE:|BID:)')
SYNDESC  = re.compile('( *Synopsis: *| *Description:)')
COMPL    = re.compile('21156\\|(1|2|3)\\|(Syntax error \([\w\d ]*\)|\"(.*)\"): ')
COMPL2   = re.compile('21156\\|(1|2|3)\\|\"(.*)\"\\|')
SNMP     = re.compile('(with the community name: [\w]+ )')
REPLACEMENTS =  [
    (' :',':'),
    ('the the','the'),
    (' interfer ',' interfere '),
    ('Security Note','1'),
    ('Security Warning','2'),
    ('Security Hole','3'),
    ('\\\\','\\'),
    ('10862|3|','10862|3|The SQL Server has a common password for one or '
     +'more accounts. These accounts may be used to gain access to the '
     +'records in the database or even allow remote command execution.|'),
    ('21725|3|','21725|3|The remote host has an out-dated version of the '
     +'Symantec Corporate virus signatures, or Symantec AntiVirus '
     +'Corporate is not running.|'),
    ('22035|2|','22035|2|The version of Adobe Acrobat installed on the '
     +'remote host is earlier than 6.0.5 and is reportedly affected by a '
     +'buffer overflow that may be triggered when distilling a specially-'
     +'crafted file to PDF.|'),
    ('34252|1|','34252|1|A Windows service is listening on this port.|'),
]

# ---------------------------------------------------------

def cleanNbe(data):
    for i, j in REPLACEMENTS:
        data = data.replace(i, j)
    data = DOTS.sub('.', data)
    data = SYNDESC.sub('', data)
    data = GMT.sub('GMT\\1|Renew the SSL certificate for the remote server.',
                   data, count=1)
    data = SOLUTION.sub('|\\1', data, count=1)
    data = COMPL.sub('21156|\\1|\\2|', data, count=1)
    data = COMPL2.sub('21156|\\1|\\2|', data)
    data = SNMP.sub('\\1|', data)
    data = PIPE.sub('|', data)
    data = FIX.sub('\\1|\\2|', data)
    data = data.rstrip(' ')
    return data

# ---------------------------------------------------------

meta = []
open_ports = []
results = []

dirty_results = file(sys.argv[1]).readlines()
clean_results = []
for line in dirty_results:
    clean_results.append(cleanNbe(line))

for line in clean_results:
    data = line.split('|')
    if 'timestamps' in data[0]:
        meta.append(data)
    elif 'results' in data[0]:
        if len(data) == 4:
            open_ports.append(data)
        else:
            results.append(data)
    else:
        pass

# build the header start and end times
scan_start = meta[0][-2]
host_connect = meta[1][-2]
host_disconnect = meta[2][-2]
scan_stop = meta[3][-2]


def clean(r):
    if r.startswith('\n\n '):
        r = r.lstrip('\n\n ')
    if r.startswith('\n\n'):
        r = r.lstrip('\n\n')
    if r.startswith(' '):
        r = r.lstrip(' ')

    r = r.replace("""\\n""", '<br>')
    if 'Overview:' in r:
        r = r.replace("Overview:", '<b>Overview:</b>')
    if 'Impact:' in r:
        r = r.replace("Impact:", '<b>Impact:</b>')
    if 'Impact Level:' in r:
        r = r.replace("Impact Level:", '<b>Impact Level:</b>')
    if 'Solution:' in r:
        r = r.replace("Solution:", '<b>Solution:</b>')
    if 'References:' in r:
        r = r.replace("References:", '<b>References:</b>')

    return r


# detailed report
high = []
medium = []
low = []

for result in results:
    if '3' in result[5]:
        result[6] = clean(result[6])
        high.append(result)
    elif '2' in result[5]:
        result[6] = clean(result[6])
        medium.append(result)
    elif '1' in result[5]:
        if result[6] == '':
            pass
        else:
            result[6] = clean(result[6])
            low.append(result)
    else:
        pass # ignore the log messages


# pie chart
#plot.figure(figsize = (3, 3))
#
#data = []
#labels = []
#explode = []
#colors = []
#
#v = (len(high), len(medium), len(low))
#l = ('High', 'Medium', 'Low')
#c = ('#ff0000', '#00ff00', '#ffff00')
#
#for i in range(0, len(v)):
#    if v[i] > 0:
#        data.append(v[i])
#        labels.append(l[i])
#        explode.append(0.05)
#        colors.append(c[i])
#
#plot.pie(data, colors = colors, explode = explode, labels = labels, autopct = None);
#plot.title('Vulnerabilities', bbox = {'facecolor': '0.9', 'pad': 15})
#
#
#filename = '/var/www/sdocs/test.finnean.com/images/scans/pie.png'
#plot.savefig(filename)

#html = Template(file='/var/www/sdocs/test.finnean.com/images/scans/forxs-scan-results.html')
#html.scan_start = scan_start
#html.scan_stop = scan_stop
#html.high = high
#html.medium = medium
#html.low = low
#
#fd = open('/var/www/sdocs/test.finnean.com/images/scans/new.html', 'w')
#fd.write(html.respond())
#fd.close()
