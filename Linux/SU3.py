"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@"
# -*- coding: utf-8 -*-
import os
import re
from pprint import pprint
result_list = []
os.chdir("/")

# SU3-01 Finger 서비스 비활성화
dt = {}
result = 0
dt['SUV'] = 'SU3-01'

cmd = os.popen("finger 2>/dev/null").read().split()
if cmd == []:
    dt['value'] = 'Finger 서비스가 중단되었습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = 'Finger 서비스가 작동 중 입니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# SU3-02 Anonymous FTP 비활성화
dt = {}
result = 0
dt['SUV'] = 'SU3-02'

cmd = os.popen("cat /etc/passwd | grep 'ftp'").read().split()
if cmd == []:
    dt['value'] = 'Anonymous FTP를 사용하지 않고있습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = 'Anonymous FTP를 사용하고 있습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# SU3-03 r 계열 서비스 비활성화
dt = {}
result = 0
dt['SUV'] = 'SU3-03'
cmd1 = os.popen(
    'ls -aIL /etc/xinetd.d/* | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec"').read().split()

if cmd == []:
    dt['value'] = '"r" 계열 서비스를 사용하고 있지 않습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = '"r" 계열 서비스를 사용하고 있습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# SU3-04 cron 파일 소유자 및 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU3-04'
cmd1 = os.popen('ls -l /etc/cron.allow').read().split()
cmd2 = os.popen('ls -l /etc/cron.deny').read().split()

if cmd1 == [] and cmd2 == []:  # 두 파일 모두 없는 경우
    dt['value'] = 'cron을 사용하고 있지 않습니다.'
    dt['status'] = 'Good'
elif cmd1 == []:
    dt['value'] = 'cron.allow 파일이 없습니다.'
    dt['status'] = 'Weak'
elif cmd2 == []:  # 한 파일만 없는 경우
    dt['value'] = 'cron.deny 파일이 없습니다.'
    dt['status'] = 'Weak'
else:  # 둘 다 있는 경우
    if cmd[2] == 'root':
        y = "".join(cmd).split(" ")
        power = y[0]
        # owner power
        if power[1] == "r":
            numpower += 4
        if power[2] == "w":
            numpower += 2
        if power[3] == "x":
            numpower += 1
        powers.append(numpower)
        numpower = 0

        # grop power
        if power[4] == "r":
            numpower += 4
        if power[5] == "w":
            numpower += 2
        if power[6] == "x":
            numpower += 1
        powers.append(numpower)
        numpower = 0

        # other power
        if power[7] == "r":
            numpower += 4
        if power[8] == "w":
            numpower += 2
        if power[9] == "x":
            numpower += 1
        powers.append(numpower)
        if powers[0] <= 6 and powers[1] <= 4 and powers[2] == 0:
            dt['value'] = 'cron 파일의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'cron 파일의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'cron 파일의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

result_list.append(dt)

# SU3-05 DoS 공격에 취약한 서비스 비활성화
dt = {}
result = 0
max_result = 0
dt['SUV'] = 'SU3-05'
cmd = os.popen(
    'ls -aIL /etc/xinetd.d/* | egrep "echo|discard|daytime|chargen"').read().split()
if cmd == []:
    dt['value'] = 'DoS 공격에 취약한 서비스가 없습니다.'
    dt['status'] = 'Good'
else:
    for x in cmd:
        max_result += 1
        cmd1 = os.popen("cat {}".format(x))
        for y in cmd1:
            text = re.sub(r"\s", "", y)
            if text == "disable=yes":
                dt['value'] = 'DoS 공격에 취약한 서비스들이 모두 비활성화 되어있습니다.'
                dt['status'] = 'Good'
                result += 1
if max_result != result:
    dt['value'] = 'DoS 공격에 취약한 서비스가 활성화 되어있습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# SU3-06 NFS 서비스 비활성화
dt = {}
result = 0
dt['SUV'] = 'SU3-06'
cmd = os.popen('ps -ef | grep "nfsd"').read().splitlines()
if cmd == []:
    dt['value'] = 'NFS 서비스가 비활성화 되어있습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = 'NFS 서비스가 활성화 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)