"""

CONFIGURATIONS

"""

""" CONFIGURATION """

IFACE           = 'enp13s0f1'
TCPDUMP         = True
EMAIL_ALERTS    = True
TWILIO_ALERTS   = True

""" TWILIO CONFIGURATION """

TWILIO_ACCOUNT_SID      = ''
TWILIO_AUTH_TOKEN       = ''
TWILIO_NUMBER           = '+12223334444'
TWILIO_TEST_SID         = ''
TWILIO_TEST_AUTH_TOKEN  = ''
TWILIO_TO               = '+15556667777'

""" 
SEND MAIL CONFIGURATION 

Requires App Password, and Less Secure Apps 

App Password : https://support.google.com/mail/?p=InvalidSecondFactor
Less Secure  : https://support.google.com/accounts/answer/6010255#more-secure-apps

"""

SMTP_HOST   = "smtp.gmail.com"
SMTP_PORT   = 465
SMTP_DOMAIN = "gmail.com"
SMTP_USER   = "someGMAILuser"
SMTP_PASS   = "password"
SMTP_TO     = 'tosomegmailuser@gmail.com'