s = \
"""
http-settings
set userAgent Fssc-fiWeb
back

plugins
output xmlFile
output config xmlFile
set fileName %s/%s.xml
back

audit all
discovery webSpider
back

target
set target %s
back

start
exit
"""
