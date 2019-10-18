#!/usr/bin/python3

"""
TCPDump Logstafeed

This Python driven script will monitor a network for connections via TCPDump.
It will covert logs into an Apache / Logstalgia accepted format and save them to a separate log file.
That file will then be redirected into Logstalgia and synced to display the logging in a visual format.

Usage:
    1. touch connections.log
    1. vim tcpdump_to_logsta.py and edit the iface var
    2. sudo ./logstafeed.py
    3. tail -F snort.log -F connections.log | logstalgia --sync

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

iface  = 'enp13s0f1'

# Format of the log. Relates to Apache logs that are supportive of Logstalgia
log = "{0}|{1}|{2}|{3}|{4}\n"

processRunning = subprocess.check_output(['ps','aux'])
running = 0

for line in processRunning.splitlines():
    # Be sure this is not already running if attempt to keep active via cron
    if "tcpdump_to_logsta" in line.decode('utf8'):
        running += 1
    if running >= 3:
        print("Appears they may be a process already running, catch it!")
        sys.exit()

    # Tcpdump logging
    f2 = subprocess.Popen(['tcpdump', '-i', iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p2 = select.poll()
    p2.register(f2.stdout)

    # While True, do our logging procedure
    while True:
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
                        dst_ip = line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")[
                                 0:len(line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")) -1]
                        dst_ip = '.'.join(str(x) for x in dst_ip)
                    except IndexError:
                        dst_ip = line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")

                    try:
                        dst_port = line.split(" IP ")[1].split(" > ")[1].split(":")[0].split(".")[4]
                    except IndexError:
                        dst_port = 'NONE'

                    message = log.format(timestamp, src_ip,
                                         "/{0}/{1}:{2}:{3}".format('TCPDUMP', src_port, dst_ip,
                                                                   dst_port), '200', '1024')

                    fh.write(message)
                    fh.close()
                except Exception as e:
                    print(e)
