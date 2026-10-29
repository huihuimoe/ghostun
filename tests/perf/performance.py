#!/usr/bin/env python3
"""Bounded-duration benchmark; report host-wide CPU as well as process/socket memory."""
import json
import os
import re
import subprocess
import time
from pathlib import Path


def ns(name, *args):
    return ['ip', 'netns', 'exec', name, *args]


def cpu():
    values = list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
    return sum(values), values[3] + values[4]


def rss(pid):
    return int(re.search(r'VmRSS:\s+(\d+)',Path(f'/proc/{pid}/status').read_text())[1])


def sockets():
    return {name: subprocess.check_output(ns(name,'ss','-Htmn','state','established'),text=True) + subprocess.check_output(ns(name,'ss','-Hwamn'),text=True) for name in ['entry','exit','fw']}


address=os.environ['ADDRESS']
args=ns('entry','iperf3','-c',address,'-p','5208','-t','4','-P','4','-J')
if os.environ['DIRECTION']=='download': args.append('-R')
start_cpu=cpu()
start=time.monotonic()
bulk=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
time.sleep(.4)
latency=subprocess.Popen(ns('entry','python3',os.environ['TOOLS'],'check',address,'--duration','3','--port','7100'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
time.sleep(.5)
memory={name:rss(os.environ[name.upper()+'_PID']) for name in ['entry','exit']}
socket_memory=sockets()
lat,err=latency.communicate(timeout=15)
assert latency.returncode==0,err
out,err=bulk.communicate(timeout=15)
assert bulk.returncode==0,err
finish_cpu=cpu()
elapsed=time.monotonic()-start
data=json.loads(out)
assert 'error' not in data,data
row={name.lower():os.environ[name] for name in ['TRANSPORT','OUTER_FAMILY','RELAY','CONDITION','INNER','DIRECTION']}
row.update(mbit_s=data['end']['sum_received']['bits_per_second']/1e6,
           latency=json.loads(lat),rss_kib=memory,sockets=socket_memory,
           system_busy_pct=100*(1-(finish_cpu[1]-start_cpu[1])/(finish_cpu[0]-start_cpu[0])),
           duration_s=elapsed)
print(json.dumps(row))
