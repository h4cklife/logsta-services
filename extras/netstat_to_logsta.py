#!/usr/bin/python3

import sys
import subprocess
import time
while True:
    result = subprocess.check_output("netstat -utn 2", shell=True)
    results = result.decode('utf8').split('\n')

    fh = open("ip.log", "a+")

    for r in results:
        if "tcp" in r or "udp" in r:
            # 1371769989|127.0.0.1|/tcp/192.168.1.13|200|1024
            log = "{0}|{1}|{2}|{3}|{4}\n"
            
            timestamp = int(time.time()) 

            head, sep, tail = r.partition(':')
            tmp_int = head.replace("tcp        0     ","")
            tmp_int = tmp_int.replace(" 0 ","")
            tmp_int = tmp_int.replace("36 ","")
            tmp_int = tmp_int.replace(" 1 ","")
            tmp_int = tmp_int.replace("72 ","")
            
            internal_host = tmp_int

            tmp_port = tail.split(" ")[0]

            internal_port = tmp_port
            

            ehead, esep, etail = tail.partition(":")
            exhead, exsep, extail = ehead[9:].partition(" ")

            external_host = extail.replace(" ", "")

            tmp_export = etail.split(" ")[0]
            external_port = tmp_export

            con_type = r[:3]

            fh.write(log.format(timestamp,internal_host,"/{0}/{1}:{2}:{3}".format(con_type,internal_port,
                                                                                  external_host,
                                                                                  external_port),'200','1024'))
    fh.close()
    time.sleep(5)
