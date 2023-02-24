"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@"
# -*- coding: utf-8 -*-

import os
from pprint import pprint
result_list = []
os.chdir("/")

# SU2-01 root 홈, 패스 디렉터리 권한 및 패스 설정
dt = {}
result = 0
dt['SUV'] = 'SU2-01'
cmd = os.popen("echo $PATH").read()
bad1 = cmd.find(".")
bad2 = cmd.find("::")

if bad1 > -1:
    if bad1 != len(cmd)-1:  # .이 문자열 끝에 없으면 취약
        dt['value'] = '.가 문자열 앞이나 중앙에 있습니다.'
        dt['status'] = 'Weak'
        result += 1
if bad2 > -1:
    if bad2 != len(cmd)-1:  # ::이 문자열 끝에 없으면 취약
        dt['value'] = '::가 문자열 앞이나 중앙에 있습니다.'
        dt['status'] = 'Weak'
        result += 1
if result == 0:
    dt['value'] = (cmd)
    dt['status'] = 'Good'
result_list.append(dt)

# SU2-02 파일 및 디렉터리 소유자 설정
dt = {}
result = 0
dt['SUV'] = 'SU2-02'
cmd1 = os.popen("find / -nouser -print 2>/dev/null").read()
cmd2 = os.popen("find / -nogroup -print 2>/dev/null").read()

if cmd1 == "":
    if cmd2 == "":
        dt['value'] = '모든 파일에 소유자가 존재합니다.'
        dt['status'] = 'Good'
    else:
        result = 412
else:
    result = 412

if result == 412:
    dt['value'] = '소유자가 존재하지 않는 파일이 있습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# SU2-03 /etc/passwd 파일 소유자 및 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU2-03'
cmd = os.popen("ls -l /etc/passwd").read().split()
if cmd == []:
    result = 404
else:
    if cmd[2] == 'root':
        y = "".join(cmd).split(" ")
        power = y[0]
        # owner powerrrr
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

        if powers[0] <= 6 and powers[1] <= 4 and powers[2] <= 4:
            dt['value'] = 'passwd의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'passwd의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'passwd의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-04 /etc/shadow 파일 소유자 및 권한 설정
dt = {}
result = 0
dt['SUV'] = 'SU2-04'
numpower = 0
cmd = os.popen("ls -l /etc/shadow").read().split()
if cmd == []:
    result = 404
else:
    if cmd[2] == 'root':
        y = "".join(cmd).split(" ")
        power = y[0]
        # owner power
        print(power[1])
        if power[1] == "r":
            numpower += 4
        if power[2] == "w":
            numpower += 2
        if power[3] == "x":
            numpower += 1
        if numpower <= 6 and power[4:10] == "------":
            dt['value'] = 'shadow의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'shadow의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'shadow의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-05 /etc/hosts 파일 소유자 및 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU2-05'
cmd = os.popen("ls -l /etc/hosts").read().split()
if cmd == []:
    result = 404
else:
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

        if powers[0] <= 6 and powers[1] <= 4 and powers[2] <= 4:
            dt['value'] = 'hosts의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'hosts의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'hosts의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-06 /etc/(x)inetd.conf 파일 소유자 및 권한 설정
dt = {}
result = 0
result1 = 0
result2 = 0
numpower = 0
dt['SUV'] = 'SU2-06'
cmd1 = os.popen("ls -l /etc/xinetd.conf").read().split()
cmd2 = os.popen("ls -l /etc/inetd.conf").read().split()
if cmd1 == []:
    result1 = 404
else:
    if cmd1[2] == 'root' and result == 1:
        if cmd1[0] == "-rw-------":
            dt['value'] = 'xinetd.conf의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'xinetd.conf의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'xinetd.conf의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if cmd2 == []:
    result2 = 404
else:
    if cmd2[2] == 'root' and result == 2:
        if cmd[2] == "-rw-------":
            dt['value'] = 'inetd.conf의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'inetd.conf의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'inetd.conf의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result1 == 404 and result2 == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)


# SU2-07 /etc/syslog.conf 파일 소유자 및 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU2-07'
cmd = os.popen("ls -l /etc/syslog.conf").read().split()
if cmd == []:
    result = 404
else:
    if cmd[2] == 'root':
        if cmd[0] == "-rw-r--r--":
            dt['value'] = 'syslog.conf의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'syslog.conf의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'syslog.conf의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-08 /etc/services 파일 소유자 및 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU2-08'
cmd = os.popen("ls -l /etc/services").read().split()
if cmd == []:
    result = 404
else:
    if cmd[2] == 'root':
        if cmd[0] == "-rw-r--r--":
            dt['value'] = 'services의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'services의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'services의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# SU2-09 SUID, SGID, Sticky bit 설정 파일 점검
dt = {}
result = 0
dt['SUV'] = 'SU2-09'
cmd = os.popen(
    "find / -user root -type f \( -perm -04000 -o -perm -02000 -o -perm -01000 \) -xdev -exec ls -al {} \; 2> /dev/null").read().splitlines()
if cmd == []:
    dt['value'] = '주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어있지 않습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = '주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
dt = {}
result = 0
dt['SUV'] = 'SU2-10'
cmd = os.popen("ls -al /etc/profile").read().split()
if cmd == []:
    result = 404
else:
    if cmd[2] == 'root':
        dt['value'] = '홈 디렉터리 환경변수 파일의 소유자가 root입니다.'
        dt['status'] = 'Good'
    else:
        dt['value'] = '홈 디렉터리 환경변수 파일의 소유자가 root가 아닙니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-11 world writable 파일 점검
dt = {}
result = 0
dt['SUV'] = 'SU2-11'
cmd = os.popen(
    "find / -type f -perm -2 -exec ls -al {} \; 2> /dev/null").read().splitlines()
if cmd == []:
    dt['value'] = 'world writable파일이 존재하지 않습니다.'
    dt['status'] = 'Good'
else:
    for x in cmd:
        y = "".join(x).split('.')
        perm = list(y[0])
        if perm[8] == 'w':
            dt['value'] = 'world writable파일이 존재합니다.'
            dt['status'] = 'Weak'
        else:
            dt['value'] = 'world writable파일이 존재하지 않습니다.'
            dt['status'] = 'Good'
result_list.append(dt)


# SU2-12 /dev에 존재하지 않는 device 파일 점검
dt = {}
result = 0
dt['SUV'] = 'SU2-12'
cmd = os.popen("find /dev -type f -exec ls -l {} \;").read().splitlines()
if cmd == []:
    dt['value'] = '/dev에 모든 파일을 점검하였습니다.'
    dt['status'] = 'Good'
else:
    for x in cmd:
        y = "".join(x).split(" ")
        if y[4] == '0':
            dt['value'] = '/dev에 옳지 않은 파일이 존재합니다.'
            dt['status'] = 'Weak'
        elif y[4] == '':
            if y[5] == '':
                dt['value'] = '/dev에 옳지 않은 파일이 존재합니다.'
                dt['status'] = 'Weak'
            else:
                dt['value'] = '/dev에 모든 파일을 점검하였습니다.'
                dt['status'] = 'Good'
        else:
            dt['value'] = '/dev에 모든 파일을 점검하였습니다.'
            dt['status'] = 'Good'
result_list.append(dt)

# SU2-13 $HOME/.rhosts, hosts.equiv 사용 금지
dt = {}
result = 0
dt['SUV'] = 'SU2-13'
cmd1 = os.popen("ls -l /etc/hosts.equiv").read().splitlines()
cmd2 = os.popen("ls -l $HOME/.rhosts").read().splitlines()
if cmd1 == []:
    if cmd2 == []:
        dt['value'] = "login, shell, exec 서비스를 사용하고 있지 않습니다."
        dt['status'] = 'Good'
    else:
        if cmd2[2] == 'root':
            y = "".join(cmd2).split(" ")
            power = y[0]
            # owner power
            if power[1] == "r":
                numpower += 4
            if power[2] == "w":
                numpower += 2
            if power[3] == "x":
                numpower += 1
            if numpower <= 6 and power[4:10] == "------":
                dt['value'] = "파일 설정이 정상적으로 되어있습니다."
                dt['status'] = 'Good'
            else:
                dt['value'] = '파일 권한이 600초과로 설정되었습니다.'
                dt['status'] = 'Weak'
        else:
            dt['value'] = '파일 소유자가 root가 아닙니다.'
            dt['status'] = 'Weak'
else:
    if cmd1[2] == 'root':
        y = "".join(cmd1).split(" ")
        power = y[0]
        # owner power
        if power[1] == "r":
            numpower += 4
        if power[2] == "w":
            numpower += 2
        if power[3] == "x":
            numpower += 1
        if numpower <= 6 and power[4:10] == "------":
            dt['value'] = "파일 설정이 정상적으로 되어있습니다."
            dt['status'] = 'Good'
        else:
            dt['value'] = '파일 권한이 600초과로 설정되었습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = '파일 소유자가 root가 아닙니다.'
        dt['status'] = 'Weak'
result_list.append(dt)


# SU2-14 접속 IP 및 포트 제한
dt = {}
result = 0
dt['SUV'] = 'SU2-14'
cmd1 = os.popen("cat /etc/hosts.denyv").read().splitlines()
cmd2 = os.popen("cat /etc/hosts.allow").read().splitlines()
cmd = os.popen("iptables -L").read().splitlines()

if cmd == []:
    if cmd1 == []:
        result = 404
    else:
        if cmd2 == []:
            result = 404
        else:
            for x in cmd1:
                if x.startswith('#'):
                    pass
                else:
                    if x == "ALL:ALL":
                        result += 1
            for x in cmd2:
                if x.startswith('#'):
                    pass
                else:
                    if x == "sshd : 192.168.0.189, 192.168.0.7":
                        result += 1
else:
    for x in cmd:
        text = x.replace(" ", "")
        if text == "ACCEPTtcp--192.168.1.0/24anywheretcpdpt:ssh":
            result += 1
        if text == "DROPtcp--anywhereanywheretcpdpt:ssh":
            result += 1

if result >= 2:
    dt['value'] = 'IP 및 포트 접속 제한 설정 완료.'
    dt['status'] = 'Good'

if result == 0:
    dt['value'] = '설정이 존재하지 않습니다.'
    dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)


# SU2-15 hosts.lpd 파일 소유자 및 권한 설정
dt = {}
result = 0
dt['SUV'] = 'SU2-15'
cmd = os.popen("ls -al /etc/hosts.lpd").read().split()
if cmd == []:
    result = 404
else:
    if cmd[2] == 'root':
        if cmd[0] == '-rw-------':
            dt['value'] = 'hosts.lpd의 파일권한 및 소유자가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'hosts.lpd의 파일권한이 정상적으로 설정되어있지 않습니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'hosts.lpd의 소유자가 정상적으로 설정되어있지 않습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# SU2-16 NIS 서비스 비활성화
dt = {}
result = 0
dt['SUV'] = 'SU2-16'
cmd = os.popen(
    'ps -ef | egrep "nfsd|statd|mountd" | grep -v grep >/dev/null 2>&1').read().split()
if cmd == []:
    dt['value'] = 'NFS 서비스가 비활성화 되어있습니다'
    dt['status'] = 'Good'
else:
    dt['value'] = 'NFS 서비스가 활성화 되어있습니다.'
    dt['status'] = 'Weak'


if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# SU2-17 UMASK 설정 관리
dt = {}
result = 0
before = ""
dt['SUV'] = 'SU2-17'
cmd = os.popen("cat /etc/profile").read().split()
if cmd == []:
    result = 404
else:
    for x in cmd:
        if x == 'umask 022' or x == 'umask 027':
            if "if" in before:
                dt['value'] = 'umask 기본 설정만 존재합니다.'
                dt['status'] = 'Weak'
            else:
                result += 1
        if x == "export umask":
            result += 1
        else:
            dt['value'] = 'umask 기본 설정만 존재합니다.'
            dt['status'] = 'Weak'
        before = x


if result == 2:
    dt['value'] = 'umask 설정이 완료되었습니다.'
    dt['status'] = 'Good'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-18 홈디렉토리 소유자 및 권한 설정
dt = {}
result = 0
bad = []
dt['SUV'] = 'SU2-18'
cmd1 = os.popen("cat /etc/passwd").read().splitlines()
if cmd1 == []:
    result = 404
else:
    for x in cmd1:
        home = "".join(x).split(":")
        cmd2 = os.popen("ls -ald {}".format(home[5])).read().splitlines()
        y = "".join(cmd2).split(" ")
        if y[2] == home[0]:
            if y[0] == "drwx------.":
                dt['value'] = '홈디렉토리 소유자 및 권한 설정이 올바르게 되어있습니다.'
                dt['status'] = 'Good'
            else:
                dt['value'] = '{} 디렉토리의 권한이 올바르지 않습니다.'.format(home[5])
                dt['status'] = 'Weak'
                break
        else:
            dt['value'] = '{} 디렉토리의 소유자가 올바르지 않습니다.'.format(home[5])
            dt['status'] = 'Weak'
            break

for x in cmd1:
    home = "".join(x).split(":")
    if home[5] == "":
        bad.append(home[0])


if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-19 홈디렉토리로 지정한 디렉토리의 존재 관리
dt = {}
result = 0
dt['SUV'] = 'SU2-19'
if bad == []:
    dt['value'] = '모든 계정에 홈 디렉토리가 존재합니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = '{} 계정에 홈 디렉토리가 존재하지 않습니다.'.format(bad[0])
    dt['status'] = 'Weak'

result_list.append(dt)


# SU2-20 숨겨진 파일 및 디렉토리 검색 및 제거
dt = {}
result = 0
dt['SUV'] = 'SU2-20'
cmd1 = os.popen('find / -type f -name ". *"').read().splitlines()
cmd2 = os.popen('find / -type d -name ". *"').read().splitlines()
if cmd1 == [] and cmd2 == []:
    dt['value'] = '숨겨진 파일이 존재하지 않습니다.'
    dt['status'] = 'Good'
else:
    if cmd1 == []:
        for x in cmd2:
            cmd = os.popen("stat {}".format(x)).read().splitlines()
            changeTime = cmd[7].split(" ")
            currentTime = cmd[5].split(" ")
            if currentTime[1] >= changeTime[1]:  # 날자 비교 1개월 이상 수정이 없다면 취약
                currentTime = "".join(currentTime[1]).split("-")
                changeTime = "".join(changeTime[1]).split("-")
                date = int(currentTime[1]) - int(changeTime[1])
                if date == 1:
                    if int(currentTime[2]) >= int(changeTime[2]):
                        dt['value'] = '의심스러운 폴더가 존재합니다.'
                        dt['status'] = 'Weak'
                elif date >= 1:
                    dt['value'] = '의심스러운 폴더가 존재합니다.'
                    dt['status'] = 'Weak'
                else:
                    dt['value'] = '의심스러운 폴더가 없습니다.'
                    dt['status'] = 'Good'
    elif cmd2 == []:
        for x in cmd1:
            cmd = os.popen("stat {}".format(x)).read().splitlines()
            changeTime = cmd[7].split(" ")
            currentTime = cmd[5].split(" ")
            if currentTime[1] >= changeTime[1]:  # 날자 비교 1개월 이상 수정이 없다면 취약
                currentTime = "".join(currentTime[1]).split("-")
                changeTime = "".join(changeTime[1]).split("-")
                date = int(currentTime[1]) - int(changeTime[1])
                if date == 1:
                    if int(currentTime[2]) >= int(changeTime[2]):
                        dt['value'] = '의심스러운 디렉토리가 존재합니다.'
                        dt['status'] = 'Weak'
                elif date >= 1:
                    dt['value'] = '의심스러운 디렉토리가 존재합니다.'
                    dt['status'] = 'Weak'
                else:
                    dt['value'] = '의심스러운 디렉토리가 없습니다.'
                    dt['status'] = 'Good'

result_list.append(dt)


# SU2-21 History file 권한 설정
dt = {}
result = 0
numpower = 0
dt['SUV'] = 'SU2-21'
cmd = os.popen("ls -ald ~/.bash_history").read().splitlines()
if cmd == []:
    result = 404
else:
    if cmd[0] == "-rw-------":
        dt['value'] = 'history 파일의 권한이 정상적으로 설정되어있습니다.'
        dt['status'] = 'Good'
    else:
        dt['value'] = 'history 파일 권한이 비정상적으로 설정되어있습니다.'
        dt['status'] = 'Weak'

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)


# SU2-22 .netrc 파일 내 호스트정보 노출
dt = {}
result = 0
numpower = 0
dt['SUV'] = 'SU2-22'
cmd = os.popen("find / -name .netrc").read().splitlines()
if cmd == []:
    dt['value'] = 'netrc 파일이 없습니다.'
    dt['status'] = 'Good'
else:
    for x in cmd:
        cmd1 = os.popen("ls -ald {}".format(x)).read().splitlines()
        if cmd1[0] == "-rw-------":
            dt['value'] = 'netrc 파일의 권한이 정상적으로 설정되어있습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'netrc 파일 권한이 비정상적으로 설정되어있습니다.'
            dt['status'] = 'Weak'
            break
result_list.append(dt)

# SU2-23 Crontab 설정파일 권한설정 오류
dt = {}
result = 0
numpower = 0
dt['SUV'] = 'SU2-23'
cmd = os.popen("ls -ald /var/spool/cron/crontabs").read().splitlines()
if cmd == []:
    dt['value'] = 'crontabs 작업이 없습니다.'
    dt['status'] = 'Good'
else:
    y = "".join(cmd).split(" ")
    power = y[0]
    # owner power
    if power[1] == "r":
        numpower += 4
    if power[2] == "w":
        numpower += 2
    if power[3] == "x":
        numpower += 1
    if numpower <= 6 and power[4:10] == "------":
        dt['value'] = 'crontabs 파일의 권한이 정상적으로 설정되어있습니다.'
        dt['status'] = 'Good'
    else:
        dt['value'] = 'crontabs 파일 권한이 비정상적으로 설정되어있습니다.'
        dt['status'] = 'Weak'
result_list.append(dt)

# SU2-24 Crontab 참조파일 권한설정 오류
dt = {}
result = 0
dt['SUV'] = 'SU2-24'
cmd = os.popen("ls -aldi /var/spool/cron/crontabs")
if cmd == []:
    dt['value'] = 'crontabs 작업이 없습니다.'
    dt['status'] = 'Good'
else:
    y = "".join(cmd).split(" ")
    cmd1 = os.popen("find / -inum {} 2>/dev/null".format(y[0]))
    for x in cmd1:
        cmd2 = os.popen("ls -ald {}".format(x))
        y = "".join(cmd2).split(" ")
        other = y[0]
        if other[7:8] == "r":
            dt['value'] = 'crontabs 참조 파일의 권한이 정상적으로 설정되어있습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'crontabs 참조 파일 권한이 비정상적으로 설정되어있습니다.'
            dt['status'] = 'Weak'
result_list.append(dt)

# SU2-25 /etc/group 파일 소유자 및 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU2-25'
cmd = os.popen("ls -ald  /etc/group")
if cmd == []:
    result = 404
else:
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

    if powers[0] <= 6 and powers[1] <= 4 and powers[2] <= 4:
        if y[2] == 'root':
            dt['value'] = 'group 파일의 소유자 및 권한설정이 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = 'group파일의 소유자가 root가 아닙니다.'
            dt['status'] = 'Weak'
    else:
        dt['value'] = 'group 파일의 권한이 비정상적으로 설정되어있습니다.'
        dt['status'] = 'Weak'


if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# SU2-26 시스템 디렉토리 권한 설정 미비
dt = {}
result = 0
count = 0
numpower = 0
link = ["/usr", "/bin", "/sbin", "/etc", "/var"]
dt['SUV'] = 'SU2-26'
for x in link:
    cmd = os.popen("ls -ald {}".format(link[count])).read().splitlines()
    if cmd == []:
        result = 404
    else:
        y = "".join(cmd).split(" ")
        other = y[0]

        # owner power
        if other[7] == "r":
            numpower += 4
        if other[8] == "w":
            numpower += 2
        if other[9] == "x":
            numpower += 1
        if numpower <= 4:
            dt['value'] = '모든 시스템 디렉토리의 권한설정이 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'
        else:
            dt['value'] = '{} 디렉토리의 권한 설정이 비정상적으로 되어있습니다.'.format(link[count])
            dt['status'] = 'Weak'
    count += 1

if result == 404:
    dt['value'] = '파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# SU2-27 C 컴파일러 존재 및 권한 설정 오류
dt = {}
result = 0
dt['SUV'] = 'SU2-27'
cmd = os.popen("gcc --version > /dev/null 2>&1").read().split()
if cmd == []:
    dt['value'] = 'C 컴파일러가 존재하지 않습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = 'C 컴파일러가 존재합니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# SU2-28 과도한 시스템 로그파일 권한 설정
dt = {}
result = 0
numpower = 0
powers = []
dt['SUV'] = 'SU2-28'
cmd = os.popen("ls /var/log").read().splitlines()
os.chdir("/var/log")
if cmd == []:
    dt['value'] = '로그 파일이 존재하지 않습니다.'
    dt['status'] = 'Good'
else:
    for logfile in cmd:
        cmd2 = os.popen("ls -ld {}".format(logfile)).read().splitlines()
        if cmd2 == []:
            pass
        else:
            y = "".join(cmd2).split(" ")
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

            if powers[0] <= 6 and powers[1] <= 4 and powers[2] <= 4:
                dt['value'] = 'C 컴파일러가 존재하지 않습니다.'
                dt['status'] = 'Good'
            else:
                dt['value'] = '{} 로그 파일의 권한이 {},{},{} 입니다.'.format(
                    logfile, powers[0], powers[1], powers[2])
                dt['status'] = 'Weak'
result_list.append(dt)

print(result_list)
