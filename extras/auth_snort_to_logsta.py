#!/usr/bin/python3

from datetime import date, datetime, timedelta
import time
import subprocess
import select
import sys
import re

running = 0
processRunning = subprocess.check_output(['ps','aux'])

for line in processRunning.splitlines():
	if "auth_snort_to_logsta" in line.decode('utf8'):
		running += 1
	if running >= 3:
		print("Appers they may be a process already running, catch it!")
		sys.exit()

	filename = "/var/log/auth.log"

	fh = open("snort.log", "a+")
	log = "{0}|{1}|{2}|{3}|{4}\n"

	f = subprocess.Popen(['tail','-F',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	p = select.poll()
	p.register(f.stdout)

	while True:
		if p.poll(1):
			line = f.stdout.readline().decode('utf8')
			#print(line+"\n")
			if "snort" in line and not "message repeated" in line:
				try:
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
					fh.write(log.format(timestamp, src_ip,
										"/{0}/{1}:{2}:{3}".format(proto, src_port, dst_host,
																  dst_port), '200', '1024'))
				except Exception as e:
					pass