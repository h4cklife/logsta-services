#!/usr/bin/python3

"""
Logstafeed

This Python driven script will monitor a network for connections via Netstat and Snort logs via auth.log.
It will covert logs into an Apache / Logstalgia accepted format and save them to a separate log file.
That file will then be redirected into Logstalgia and synced to display the logging in a visual format.
Leet right?
Enjoy!

This script may run better split into 2 scripts, but I wanted them combined, so FTW. Here is the combined version.

Check the extras directory for the originals. (May need modified and may not be up to date)

Usage:
    1. mv example_config.py to config.py
    2. vim config.py, apply your configurations
    3. python3 logstafeed.py
    4. tail -F snort.log | logstalgia --sync

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

running = 0
timeout = 5

# Format of the log. Relates to Apache logs that are supportive of Logstalgia
log = "{0}|{1}|{2}|{3}|{4}\n"

processRunning = subprocess.check_output(['ps','aux'])

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

        # Netstat connection logs
        result = subprocess.check_output("netstat -utn 2", shell=True)
        results = result.decode('utf8').split('\n')
        for r in results:
            if "tcp" in r or "udp" in r:
                fh = open("snort.log", "a+")

                timestamp = int(time.time())

                head, sep, tail = r.partition(':')
                tmp_int = head.replace("tcp        0     ", "")
                tmp_int = tmp_int.replace(" 0 ", "")
                tmp_int = tmp_int.replace("36 ", "")
                tmp_int = tmp_int.replace(" 1 ", "")
                tmp_int = tmp_int.replace("72 ", "")

                internal_host = tmp_int

                tmp_port = tail.split(" ")[0]

                internal_port = tmp_port

                ehead, esep, etail = tail.partition(":")
                exhead, exsep, extail = ehead[9:].partition(" ")

                external_host = extail.replace(" ", "")

                tmp_export = etail.split(" ")[0]
                external_port = tmp_export

                con_type = r[:3]

                # Example of the output
                # 1371769989|127.0.0.1|/tcp/192.168.1.15|200|1024
                message = log.format(timestamp, internal_host, "/{0}/{1}:{2}:{3}".format(con_type, internal_port,
                                    external_host, external_port), '200', '1024')

                fh.write(message)

                fh.close()
        time.sleep(timeout)
