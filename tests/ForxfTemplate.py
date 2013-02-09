s = \
"""
http-settings
set userAgent Fssc-ForX
back

plugins
output xmlFile
output config xmlFile
set fileName %s/%s.xml
back

audit sqli, xss
discovery webSpider
grep all
back

target
set target %s
back

start
exit
"""
