#!/usr/bin/python3

"""
Logstafeed


This Python driven script will monitor a network for connections via TCPDump and Snort logs via auth.log.
It will covert logs into an Apache / Logstalgia accepted format and save them to a separate log file.
That file will then be redirected into Logstalgia and synced to display the logging in a visual format.
Leet right?
Enjoy!

Check the extras directory for the originals. (May need modified and may not be up to date)

Usage:
    1. mv example_config.py to config.py
    2. vim config.py and apply your configurations
    3. touch snort.log
    4. touch connections.log
    5. sudo ./logstafeed.py
    6. tail -F snort.log -F connections.log | logstalgia --sync

Developed by: @h4cklife

"""
import config
import time
import subprocess
import select
import sys
import re
import smtplib
from twilio.rest import Client
from datetime import date, datetime, timedelta

# Format of the log. Relates to Apache logs that are supportive of Logstalgia
log = "{0}|{1}|{2}|{3}|{4}\n"

processRunning = subprocess.check_output(['ps','aux'])
running = 0

def send_twilio_sms(to, message):
    """
    send_twilio_sms(to, message)

    :param to:
    :param message:
    :return:

    Send a SMS message to the client using our Twilio API

    """
    if config.TWILIO_ALERTS:
        client = Client(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN)
        message_instance = client.messages.create(
            to="{0}".format(config.TWILIO_TO),
            from_=config.TWILIO_NUMBER,
            body=message)

        return message_instance.sid

def sendmail(to, body):
    """
    sendmail(to, body)

    :param to:
    :param body:
    :return:

    Send an email

    """
    if config.EMAIL_ALERTS:
        sent_from = "{0}@{1}".format(config.SMTP_USER, config.SMTP_DOMAIN)
        subject = '{0} - Threat Identification'.format('IDS')

        email_text = """  
        From: {0}\nTo: {1}\nSubject: {2}\n\n{3}
        """.format("{0}@{1}".format(config.SMTP_USER, config.SMTP_DOMAIN), to, subject, body)

        try:
            server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT)
            server.ehlo()
            server.login("{0}@{1}".format(config.SMTP_USER, config.SMTP_DOMAIN), config.SMTP_PASS)
            server.sendmail("{0}@{1}".format(config.SMTP_USER, config.SMTP_DOMAIN), to, email_text)
            server.close()
        except Exception as e:
            print(e)

for line in processRunning.splitlines():
    # Be sure this is not already running if attempt to keep active via cron
    if "logstafeed" in line.decode('utf8'):
        running += 1
    if running >= 3:
        print("Appears they may be a process already running, catch it!")
        sys.exit()

    # Snort logging via auth.log
    filename = "/var/log/auth.log"
    f = subprocess.Popen(['tail','-F',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    f2 = None
    p2 = None
    if config.TCPDUMP:
        # Tcpdump logging
        f2 = subprocess.Popen(['tcpdump', '-i', config.IFACE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = select.poll()
        p2.register(f2.stdout)

    # While True, do our logging procedure
    while True:
        if p.poll(1):
            # Auth.log Snort logs
            line = f.stdout.readline().decode('utf8')
            #print(line+"\n")
            if "snort" in line and not "message repeated" in line:
                try:
                    # Parsing of the auth.log snort log
                    fh = open("snort.log", "a+")
                    timestamp = int(time.time())
                    src_ip = (line.split("{TCP} "))[1].split(":")[0]
                    src_port = (line.split(":"))[8].split(" ")[0]
                    dst_ip = (line.split("-> "))[1].split(":")[0]
                    dst_host = (line.split(" "))[3].split("snort[")[0]
                    dst_port = (line.split(":"))[9].split("\n")[0]
                    gid = (line.split(": ["))[1].split(":")[0]
                    sid = (line.split(":"))[4].split(":")[0]
                    rid = (line.split(":"))[5].split("]")[0]
                    desc = (line.split("] "))[1].split(" [")[0]
                    classifi = (line.split("Classification: "))[1].split("]")[0]
                    priority = (line.split("[Priority: "))[1].split("]")[0]
                    proto = (line.split("{"))[1].split("}")[0]

                    # Example of the output
                    # 1571270436|192.168.10.5|/TCP/49418:SomeHost:6667|200|1024
                    message = log.format(timestamp, src_ip,
										"/{0}/{1}:{2}:{3}".format(proto, src_port, dst_host,
																  dst_port), '200', '1024')
                    fh.write(message)

                    # Send email and text alerts for Snort logs : Needs some limits
                    send_twilio_sms(config.TWILIO_NUMBER, message)
                    sendmail(config.SMTP_TO, message)

                    fh.close()
                except Exception as e:
                    print(e)

        if config.TCPDUMP:
            if p2.poll(1):
                # Auth.log Snort logs
                line = f2.stdout.readline().decode('utf8')
                # print(line+"\n")
                if "IP" in line and not "sccoast" in line and not "IP6" in line:
                    try:
                        # Parsing of the auth.log snort log
                        fh = open("connections.log", "a+")

                        timestamp = int(time.time())

                        try:
                            src_ip = line.split(" IP ")[1].split(" > ")[0].split(".")[0:4]
                            src_ip = '.'.join(str(x) for x in src_ip)
                        except IndexError:
                            src_ip = line.split(" IP ")[1].split(" > ")[0]

                        try:
                            src_port = line.split(" IP ")[1].split(" > ")[0].split(".")[4]
                        except IndexError:
                            src_port = 'NONE'

                        try:
                            dst_ip = line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")[0:len(line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")) -1]
                            dst_ip = '.'.join(str(x) for x in dst_ip)
                        except IndexError:
                            dst_ip = line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")

                        try:
                            dst_port = line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")[4]
                        except IndexError:
                            dst_port = 'NONE'

                        # Example of the output
                        # 1571270436|192.168.10.5|/TCP/49418:SomeHost:6667|200|1024
                        message = log.format(timestamp, src_ip,
                                             "/{0}/{1}:{2}:{3}".format('TCPDUMP', src_port, dst_ip,
                                                                       dst_port), '200', '1024')

                        fh.write(message)
                        fh.close()
                    except Exception as e:
                        print(e)
