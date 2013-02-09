#!/usr/bin/env python
import cgi

try:
    from elementtree import ElementTree as et
except ImportError:
    from xml.etree import ElementTree as et


class fiWebParser(object):
    def __init__(self, filename = None):
        self.filename = filename
        self.high = []
        self.medium = []
        self.low = []
    def setFilename(self, f):
        self.filename = f
    def parse(self):
        root = et.parse(self.filename)
        vulnerabilities = root.findall('vulnerability')

        dtmp = {}
        for vulnerability in vulnerabilities:
            if 'error500' not in vulnerability.get('plugin'): # We dont want any scan errors
                if vulnerability.get('severity').upper() == 'HIGH':
                    for k,v in vulnerability.items():
                        dtmp[k] = v
                        desc = vulnerability.text
                        desc = desc.lstrip()
                        desc = desc.rstrip()
                        dtmp['description'] = cgi.escape(desc)
                    self.high.append(dtmp)
                    dtmp = {}
                elif vulnerability.get('severity').upper() == 'MEDIUM':
                    for k,v in vulnerability.items():
                        dtmp[k] = v
                        desc = vulnerability.text
                        desc = desc.lstrip()
                        desc = desc.rstrip()
                        dtmp['description'] = cgi.escape(desc)
                    self.medium.append(dtmp)
                    dtmp = {}
                if vulnerability.get('severity').upper() == 'LOW':
                    for k,v in vulnerability.items():
                        dtmp[k] = v
                        desc = vulnerability.text
                        desc = desc.lstrip()
                        desc = desc.rstrip()
                        dtmp['description'] = cgi.escape(desc)
                    self.low.append(dtmp)
                    dtmp = {}

    def getHigh(self):
        return self.high
    def getMedium(self):
        return self.medium
    def getLow(self):
        return self.low
