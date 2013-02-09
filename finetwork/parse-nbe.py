#!/usr/bin/env python

# trying to parse the openvas nbe results
# open the file and read all

import re
import sys

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
    data = data.replace('\\n', ' ')
    data = ' '.join(data.split())
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

print
print "****************************************"
print "SCAN START:", scan_start
print "HOST CONNECT:", host_connect
print
print "HOST DISCONNECT:", host_disconnect
print "SCAN STOP:", scan_stop
print "****************************************"
print
print
print "****************************************"
print "PORTS CURRENTLY ACTIVE/OPEN:"
for port in open_ports:
    port_info = port[-1]
    if '\n' in port_info:
        port_info = port_info.replace('\n', '')
    print port_info

print "****************************************"
print
print

high = []
medium = []
low = []

for result in results:
    if '3' in result[5]:
        high.append(result)
    elif '2' in result[5]:
        medium.append(result)
    elif '1' in result[5]:
        low.append(result)
    else:
        pass # ignore the log messages


print "****************************************"
print "RISK SUMMARY:"
print "HIGH LEVEL:", len(high)
print "MEDIUM LEVEL:", len(medium)
print "LOW LEVEL:", len(low)
print "****************************************"

if len(high) > 0:
    for h in high:
        print "HOST:", h[2]
        print "RISK LEVEL: HIGH"
        print "TCP PORT:", h[3]
        print
        issue = h[6].split('Fix:')[0]
        fix = h[6].split('Fix:')[-1]
        print "ISSUE:", issue
        print
        print "REMEDIATION:", fix
        print
        print "REFERENCES:", h[7]
        print

if len(medium) > 0:
    for m in medium:
        print "HOST:", m[2]
        print "RISK LEVEL: MEDIUM"
        print "TCP PORT:", m[3]
        print
        issue = m[6].split('Fix:')[0]
        fix = m[6].split('Fix:')[-1]
        print "ISSUE:", issue
        print
        print "REMEDIATION:", fix
        print
        print "REFERENCES:", m[7]
        print

if len(low) > 0:
    for l in low:
        print "HOST:", l[2]
        print "RISK LEVEL: LOW"
        print "TCP PORT:", l[3]
        print
        print "ISSUE:", l[6]
        print
