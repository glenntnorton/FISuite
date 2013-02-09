#!/usr/bin/env python
import smtplib

# send confirmation email
smtp = smtplib.SMTP('mail.finnean.com')
sender = 'no-reply@finnean.com'
recipient = "kaankarayel@yahoo.com"
subject = 'Fssc-Forx Online Edition Scan Progress Update'

headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
    sender, recipient, subject
)

html = '''
<html>
<body>
<h3>Fssc Forx Online Edition Update</h3>
<p>
Your scan is still running.<br>Reports indicate that &quot;http://www.kefindustrial.com/&quot; is a large website.<br>
You will be notified upon completion.<br>
If you experience any disruption in your website service and wish to cancel the scan,<br>
send a cancel request to: <a href="mailto:"info@finnean.com">info@finnean.com</a><br><br>
Thank You - Fssc</p>'''
msg = headers + html
smtp.sendmail(sender, recipient, msg)

# ---------------------------------------------------------

smtp.close()
