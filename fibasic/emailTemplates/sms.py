#!/usr/bin/env python
import smtplib

# send confirmation email
smtp = smtplib.SMTP('smtp.finnean.com')
smtp.set_debuglevel(10)
sender = 'gnorton@finnean.com'
recipient = "5154233955@vtext.com"
txt = '''This is a test.'''
smtp.sendmail(sender, [recipient], txt)

# ---------------------------------------------------------

smtp.close()
