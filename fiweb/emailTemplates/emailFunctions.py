#!/usr/bin/env python
# emailFunctions.py
# general email utilities

import smtplib

host = 'mail.finnean.com'
sender = 'no-reply@finnean.com'
cc = 'admin@finnean.com'


def scanTimeout(rcpt, url):
    smtp = smtplib.SMTP(host)
    recipient = rcpt
    subject = 'fi-Basic Free Web Vulnerability Scanner: Max Scan Time Reached'
    headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
        sender, recipient, subject
    )

    html = '''
<html>
<body>
<h3>Finnean-SSC fi-Basic Free Web Vulnerability Scanner</h3>
<p>
1 hour scan time limit has been reached for requested scan  URL: "%s".<br><br>
Please consider a full version subscription <a href="https://www.finnean.com/fi-web.html">available here</a> to eliminate this time limit.<br><br>
Scan removed from queue.<br>
<br><br>
Thank You,
Finnean-SSC/p>''' % url

    msg = headers + html
    smtp.sendmail(sender, [recipient, cc], msg)
    smtp.close()

def scanStart(rcpt, url):
    smtp = smtplib.SMTP(host)
    recipient = rcpt
    subject = 'fi-Basic Scanner: Requested scan has started.'
    headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
        sender, recipient, subject
    )

    html = '''
<html>
<body>
<h3>Finnean-SSC fi-Basic Free Web Vulnerability Scanner</h3>
<p>
This is a notification that the fi-Basic scan has started for URL: "%s".<br><br>
A follow up notification will be sent to this email address when the scan has completed.<br><br>
Thank you for using the fi-Basic scanner.<br>
<br><br>
Finnean-SSC</p>''' % url

    msg = headers + html
    smtp.sendmail(sender, [recipient, cc], msg)
    smtp.close()

def fileNotFound(rcpt, url):
    smtp = smtplib.SMTP(host)
    recipient = rcpt
    subject = 'fi-Basic Scanner: Required file not found.'
    headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
        sender, recipient, subject
    )

    html = '''
<html>
<body>
<h3>Finnean-SSC fi-Basic Free Web Vulnerability Scanner</h3>
<p>
This is a notification that the fi-Basic scanner required server file "fibasic.txt" was not found at URL: "%s".<br><br>
The requested scan has been removed from the system queue. You may re-submit at any time.<br>
<br><br>
Finnean-SSC</p>''' % url

    msg = headers + html
    smtp.sendmail(sender, [recipient, cc], msg)
    smtp.close()

def keyMismatch(rcpt, url):
    smtp = smtplib.SMTP(host)
    recipient = rcpt
    subject = 'fi-Basic Scanner: Server file key mismatch.'
    headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
        sender, recipient, subject
    )

    html = '''
<html>
<body>
<h3>Finnean-SSC fi-Basic Free Web Vulnerability Scanner</h3>
<p>
This is a notification that the fi-Basic scanner required key contained in file "fibasic.txt" does not match our data for URL: "%s".<br><br>
The requested scan has been removed from the system queue. You may re-submit at any time.<br>
<br><br>
Finnean-SSC</p>''' % url

    msg = headers + html
    smtp.sendmail(sender, [recipient, cc], msg)
    smtp.close()

def scanComplete(rcpt, url, href):
    smtp = smtplib.SMTP(host)
    recipient = rcpt
    subject = 'fi-Basic Scanner: Scan completed.'
    headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
        sender, recipient, subject
    )

    html = '''
<html>
<body>
<h3>Finnean-SSC fi-Basic Free Web Vulnerability Scanner</h3>
<p>
This is a notification that the fi-Basic scanner has successfully completed for URL: "%s".<br><br>
Please <a href="%s">click here</a> to view your scan results.<bra<br>
Thank you for using the fi-Basic scanner.<br><br>
<br><br>
Finnean-SSC</p>''' % (url, href)

    msg = headers + html
    smtp.sendmail(sender, [recipient, cc], msg)
    smtp.close()
