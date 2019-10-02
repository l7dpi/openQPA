#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
@author zhuzhu
@contact QQ327909056
'''

rule=['GET ','POST','HEAD','GET','POS','HEA',']PO',']HE']
show=['GET ','',]
BUA='.*(WebKit|Gecko|MSIE|Konqueror|Chrome|Opera|WinHttp|Dalvik|Apache|GeoServices|AppleCoreMedia|Agent: ios|Agent: Android)'
BTL='.*(\.html HTTP|\.htm HTTP|\.jpg HTTP|\.png HTTP|\.js HTTP|\.gif HTTP|\.php HTTP|\.ico HTTP|\.css HTTP|\.json HTTP|\.xml HTTP|\.png\?|\.php\|\.htm\?|\.html\?|\.aspx\?|\.gif\?|\.js\?|\.css\?|\.json\?|\.jpg!)'
BQLM='.*(\?.*(=|\|).*&)'
BQLS='.*(\?.*(=|\|).*)'

#报长&内容
maxpl = 16
maxpc = 16

