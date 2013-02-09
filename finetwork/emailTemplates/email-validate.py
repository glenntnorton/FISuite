#!/usr/bin/env python
import smtplib

# send confirmation email
smtp = smtplib.SMTP('mail.finnean.com')
sender = 'auth@finnean.com'
recipient = "wesamzalouk@yahoo.com"
subject = 'Fssc Forx Online Edition Scanner: Further Authorization Required'

headers = "MIME-Version: 1.0\r\nContent-type: text/html;charset=utf-8\r\nFrom: %s\r\nTo:%s\r\nSubject: %s\r\n\r\n" % (
    sender, recipient, subject
)

html = '''
<html>
<body>
<h3>Fssc Forx Online Edition</h3>
<h3>Authorization/Justification Required</h3>

<p>
Hello,<br>
You or someone from this email address has requested a vulnerability scan for URL: "http://www.mysite.com/".<br>
This email is automatically sent when the web and email doamins do not match.<br><br>

If you are indeed authorized to scan this URL as you have stated by agreeing to our 
<a href="https://www.finnean.com/tos.html">Terms of Service</a>, further justification is required.<br><br>


As you have stated that you are the "Owner", Please reply to this email with proper documentation for 
"http://www.mysite.com/" within 24 hours to keep the scan request in our active queue.<br>
<br><br>
Thank You
The Fssc Team</p>'''
msg = headers + html
smtp.sendmail(sender, recipient, msg)

# ---------------------------------------------------------

smtp.close()
