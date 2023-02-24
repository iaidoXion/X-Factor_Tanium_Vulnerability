# -*- coding: utf-8 -*-
"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@"
import os
import re

result_list = []
os.chdir("/")
goodacount = 0  # max 7
# su1-01
dt = {}
result = 0
dt['SUV'] = 'SU1-01'

cmd = os.popen("cat etc/securetty").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 securetty 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if x.startswith('pts/'):
            dt['value'] = ('securetty파일에 {}설정이 존재 합니다.'.format(x))
            dt['status'] = 'Weak'
            result += 1
            break
        cm = os.popen("cat /etc/pam.d/login").read().splitlines()
        for x in cm:
            text = re.sub(r"\s", "", x)
            if text == "authrequired/lib/security/pam_securetty.so":
                dt['value'] = (x)
                dt['status'] = 'Good'
                result = 200
                break
            elif text == "#authrequired/lib/security/pam_securetty.so":
                result = 400

if result == 0:
    dt['value'] = 'login 파일의 auth required /lib/security/pam_securetty.so 설정이 존재하지 않습니다.'
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-02
dt = {}
result = 0
dt['SUV'] = 'SU1-02'
minlen = 0
lcredit = 0
dcredit = 0
ocredit = 0
data = ["minlen", "lcredit", "dcredit", "ocredit"]
i = 0
have = 0
cmd = os.popen("cat etc/pam.d/system-auth").read().splitlines()
if cmd == []:
    dt['value'] = '/etc/pam.d/에 system-auth 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if "password" in x:
            if "requisite" in x:
                if "/lib/security/$ISA/pam_cracklib.so" in x:
                    if x.startswith('#'):
                        have = 400
                    else:
                        i = 0
                        minlen = 0
                        lcredit = 0
                        dcredit = 0
                        ocredit = 0
                        # 변수 생성
                        for test in data:
                            i += 1
                            if test in x:
                                password = x.split(test)
                                numbers = re.findall(r'\d+', password[1])
                                intnumber = list(map(int, numbers))
                                if i == 1:
                                    minlen = 1
                                elif i == 2:
                                    lcredit = 1
                                elif i == 3:
                                    dcredit = 1
                                elif i == 4:
                                    ocredit = 1
                                globals()['pass{}'.format(i)] = intnumber[0]
                                if i > 1:
                                    globals()['dashIn{}'.format(i - 1)] = password[1]
                        if minlen == 1:
                            if pass1 >= 8:
                                result += 1
                            else:
                                dt['value'] = "패스워드 최소길이가 8 미만입니다."
                                dt['status'] = 'Weak'
                                result += 1
                                break
                        if lcredit == 1:
                            if pass2 == 1:
                                text = dashIn1.replace(" ", "")
                                if text.startswith('=-'):
                                    result += 1
                                else:
                                    dt['value'] = "영문 필수"
                                    dt['status'] = 'Weak'
                                    result += 1
                                    break
                        if dcredit == 1:
                            if pass3 == 1:
                                text = dashIn2.replace(" ", "")
                                if text.startswith('=-'):
                                    result += 1
                                else:
                                    dt['value'] = "숫자 필수"
                                    dt['status'] = 'Weak'
                                    result += 1
                                    break
                        if ocredit == 1:
                            if pass4 == 1:
                                text = dashIn3.replace(" ", "")
                                if text.startswith('=-'):
                                    result += 1
                                else:
                                    dt['value'] = "특수문자 필수"
                                    dt['status'] = 'Weak'
                                    result += 1
                                    break

if have == 400 and result != 4:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'

if result >= 1 and result < 4:
    dt['value'] = "일부 패스워드가 존재하지 않습니다."
    dt['status'] = 'Weak'

if result >= 4:
    goodacount += 1
    dt['value'] = "패스워드가 정상적으로 설정되었습니다."
    dt['status'] = 'Good'

if result == 0:
    dt['value'] = "system-auth 파일에 password requisite /lib/security/$ISA/pam_cracklib.so 설정이 존재하지 않습니다."
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-03
dt = {}
result = 0
dt['SUV'] = 'SU1-03'

cmd = os.popen("cat /etc/pam.d/system-auth").read().splitlines()
if cmd == []:
    dt['value'] = '/etc/pam.d에 system-auth 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if "auth" in x:
            if "required" in x:
                if "/lib/security/pam_tally.so deny" in x:
                    setting = x.split('deny')
                    numbers = re.findall(r'\d+', setting[1])
                    intnumbers = list(map(int, numbers))
                    if x.startswith('#'):
                        result = 400
                    else:
                        result = 0
                        if intnumbers[0] <= 5:
                            result += 1
                        else:
                            dt['value'] = "deny의 값이 5 이하입니다."
                            dt['status'] = 'Weak'
        text = re.sub(r"\s", "", x)
        if text == "accountrequired/lib/security/pam_tally.sono_magic_rootreset":
            if x.startswith('#'):
                result = 400
            else:
                goodacount += 1
                dt['value'] = (x)
                dt['status'] = 'Good'
                break
        else:
            dt['value'] = ('루트에 패스위드 잠금이 설정되어 있습니다.')
            dt['status'] = 'Weak'

if result == 0:
    dt['value'] = "system-auth 파일에  auth required /lib/security/pam_tally.so 설정이 존재하지 않습니다."
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-04
dt = {}
result = 0
dt['SUV'] = 'SU1-04'

cmd = os.popen("cat /etc/passwd").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 passwd 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    cm = os.popen('cat /etc/shadow').read().splitlines()
    if cm == []:
        for x in cmd:
            acount = "".join(x).split(':')
            if x.startswith('#'):
                result = 400
            else:
                if acount[1] == 'x':
                    dt['value'] = '패스워드에 암호화가 정상적으로 설정되어있습니다.'
                    dt['status'] = 'Good'
                    result += 1
                    goodacount += 1
                else:
                    dt['value'] = '패스워드에 암호화가 비정상적으로 설정되어 있습니다.'
                    dt['status'] = 'Good'
    else:
        dt['value'] = '쉐도우 패스워드를 사용하고있습니다.'
        dt['status'] = 'Good'
        result += 1
        goodacount += 1

if result == 0:
    dt['value'] = '/etc에 shadow 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)
# su1-05 root 이외의 uid가 0
dt = {}
result = 0
dt['SUV'] = 'SU1-05'

cmd = os.popen("cat /etc/passwd").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 passwd 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
for x in cmd:
    y = x.split(":")
    if y[2] == '0':
        if y[0] == "root":
            pass
        else:
            if y[0].startswith('#'):
                pass
            else:
                dt['value'] = ('{} 계정의 UID가 0번 입니다.'.format(y[0]))
                dt['status'] = 'Weak'
                break
    else:
        dt['value'] = 'root 계정만 UID 0번을 사용하고 있습니다.'
        dt['status'] = 'Good'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-06
dt = {}
result = 0
dt['SUV'] = 'SU1-06'
suGroup = 'wheel'
nocommen = 0

cmd = os.popen("cat /etc/group").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 group 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if x.startswith("#"):
            result = 400
        else:
            acount = x.split(':')
            if acount[0] == suGroup:
                if acount[3] == "":
                    dt['value'] = '{} 그룹에 구성원이 존재하지 않습니다.'.format(suGroup)
                    dt['status'] = 'Weak'
                    result += 1
                    break
                else:
                    cm = os.popen("cat /etc/pam.d/su").read().splitlines()
                    if cm == []:
                        dt['value'] = '/etc/pam.d 에 su 파일이 존재하지 않습니다.'
                        dt['status'] = 'Weak'
                        result = 404
                    else:
                        for x in cm:
                            text = re.sub(r"\s", "", x)
                            result = 402
                            if text == "#authrequired/lib/security/pam_{}.sodebuggroup={}".format(suGroup, suGroup) or text == "#authrequired/lib/security/$ISA/pam_{}.souse_uid".format(suGroup):
                                nocommen = 400
                            elif text == "authrequired/lib/security/pam_{}.sodebuggroup={}".format(suGroup, suGroup) or text == "authrequired/lib/security/$ISA/pam_{}.souse_uid".format(suGroup):
                                dt['value'] = '특정 그룹만 su명령어를 사용할 수 있개 변경하였습니다.'
                                dt['status'] = 'Good'
                                result = 200
                                break

if result == 0:
    dt['value'] = '{} 그룹이 없습니다.'.format(suGroup)
    dt['status'] = 'Weak'

if nocommen == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'

if result == 402 and nocommen != 400:
    dt['value'] = '/etc/pam.d/su 에 설정이 존재하지 않습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# su1-07 패스워드 최소 길이 설정
dt = {}
result = 0
dt['SUV'] = 'SU1-07'
cmd = os.popen("cat /etc/login.defs").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 login.defs 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if "PASS_MIN_LEN" in x:
            numbers = re.findall(r'\d+', x)
            intnumbers = list(map(int, numbers))
            if x.startswith('#'):
                result = 400
                pass
            elif intnumbers == []:
                dt['value'] = 'PASS_MIN_LEN에 값이 존재하지 않습니다.'
                dt['status'] = 'Weak'
                result += 1
            elif intnumbers[0] >= 8:
                dt['value'] = (x)
                dt['status'] = 'Good'
                result += 1
                goodacount += 1
                break
            else:
                dt['value'] = '패스워드의 최소길이가 8 미만으로 설정되어 있습니다.'
                dt['status'] = 'Weak'
                result += 1
                break
if result == 0:
    dt['value'] = "login.defs 파일에 PASS_MIN_LEN 설정이 존재하지 않습니다."
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# su1-08 패스워드 최대 사용 기간 설정
dt = {}
result = 0
dt['SUV'] = 'SU1-08'

cmd = os.popen("cat /etc/login.defs").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 login.defs 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if "PASS_MAX_DAYS" in x:
            numbers = re.findall(r'\d+', x)
            intnumbers = list(map(int, numbers))
            if x.startswith('#'):
                result = 400
                pass
            elif intnumbers == []:
                dt['value'] = 'PASS_MAX_DAYS에 값이 존재하지 않습니다.'
                dt['status'] = 'Weak'
                result += 1
            elif intnumbers[0] <= 90:
                dt['value'] = (x)
                dt['status'] = 'Good'
                result += 1
                goodacount += 1
                break
            else:
                dt['value'] = '패스워드 최대 사용기간이 {}일 로 설정되어 있습니다.'.format(
                    intnumbers[0])
                dt['status'] = 'Weak'
                result += 1
                break

if result == 0:
    dt['value'] = "login.defs 파일에 PASS_MAX_DAYS 설정이 존재하지 않습니다."
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-09 패스워드 최소 사용기간 설정
dt = {}
result = 0
dt['SUV'] = 'SU1-09'

cmd = os.popen("cat /etc/login.defs").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 login.defs 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        if 'PASS_MIN_DAYS' in x:
            numbers = re.findall(r'\d+', x)
            intnumbers = list(map(int, numbers))
            if x.startswith('#'):
                result = 400
                pass
            elif intnumbers == []:
                dt['value'] = 'PASS_MIN_DAYS에 값이 존재하지 않습니다.'
                dt['status'] = 'Weak'
                result += 1
                break
            elif intnumbers[0] >= 1:
                dt['value'] = (x)
                dt['status'] = 'Good'
                result += 1
                goodacount += 1
                break
            else:
                dt['value'] = 'PASS_MIN_DAYS의 기한이 1 이하입니다.'
                dt['status'] = 'Weak'
                result += 1
                break
if result == 0:
    dt['value'] = "login.defs 파일에 PASS_MIN_DAYS 설정이 존재하지 않습니다."
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-10 불필요한 계정 제거
dt = {}
result = 0
dt['SUV'] = 'SU1-10'
cmd1 = os.popen("cat /etc/passwd").read().splitlines()
cmd2 = os.popen("lastlog -b 15").read().splitlines()
if cmd1 == []:
    dt['value'] = '/etc에 passwd 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd1:
        y = x.split(':')
        if "lp" == y[0] or "uucp" == y[0] or "nuucp" == y[0]:
            if x.startswith('#'):
                pass
            else:
                dt['value'] = '불필요한  Default 계정이 존재합니다. '
                dt['status'] = 'Weak'
                result += 1
                break
        elif cmd2 == []:
            dt['value'] = '로그인 로그가 없습니다.'
            dt['status'] = 'Weak'
        else:
            cmd2.pop(0)
            for x in cmd2:
                y = x.split('**')
                if y[1] == "Never logged in":
                    dt['value'] = '불필요한 계정이 존재합니다.'
                    dt['status'] = 'Weak'
                else:
                    dt['value'] = '불필요한 계정이 모두 재거되었습니다.'
                    dt['status'] = 'Good'
result_list.append(dt)

# su1-11 관리자 그룹에 최소한의 계정 포함
dt = {}
result = 0
dt['SUV'] = 'SU1-11'
cmd = os.popen("cat /etc/group").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 group 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        acount = x.split(':')
        if acount[0] == "root" and "root" in acount[3]:
            acount = acount[3].split(',')
            if len(acount) <= 1:
                if x.startswith('#'):
                    result = 400
                else:
                    dt['value'] = (x)
                    dt['status'] = 'Good'
                    break
            else:
                dt['value'] = ('관리자 그룹에 불필요한 계정이 {}개 있습니다.').format(
                    len(acount) - 1)
                dt['status'] = 'Weak'
                break
        else:
            if x.startswith('#'):
                result = 400
            else:
                dt['value'] = 'root 그룹에 root 계정이 존재하지 않습니다.'
                dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-12 계정이 존재하지 않는 GID 금지
dt = {}
result = 0
last = 0

dt['SUV'] = 'SU1-12'
cmd1 = os.popen("cat /etc/group").read().splitlines()
cmd2 = os.popen("cat /etc/passwd").read().splitlines()
if cmd1 == []:
    dt['value'] = '/etc에 group 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd1:
        last = 0
        grop = x.split(':')
        gropmamber = grop[3].split(',')
        result = 0
        if cmd2 == []:
            dt['value'] = '/etc에 passwd 파일이 존재하지 않습니다.'
            dt['status'] = 'Weak'
            result = 404
        else:
            for x in cmd2:
                if x.startswith('#'):
                    result = 400
                else:
                    acount = "".join(x).split(':')
                    for x in gropmamber:
                        if x == [""]:
                            pass
                        else:
                            if x in acount[0]:
                                last += 1
        if last < len(gropmamber):
            dt['value'] = '그룹에 존재하지 않는 계정이 있습니다.'
            dt['status'] = 'Weak'
            break
        else:
            dt['value'] = '모든 GID 가 정상적으로 설정되었습니다.'
            dt['status'] = 'Good'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-13 동일한 UID 금지
dt = {}
result = 0
uid = []
dt['SUV'] = 'SU1-13'
cmd = os.popen("cat /etc/passwd").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 passwd 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        y = x.split(":")
        if (len(uid) != 0):
            uidx = ",".join(uid).find(y[2])
            if x.startswith('#'):
                uid.append("#")
                pass
            else:
                if uidx >= 0:
                    dt['value'] = '{} 계정의 UID가 동일합니다.'.format(y[0])
                    dt['status'] = 'Weak'
                    break
                uid.append(y[2])
        elif (len(uid) == 0):
            uid.append(y[2])
        if len(cmd) == len(uid):
            dt['value'] = '모든 UID가 겹치지 않게 설정되었습니다.'
            dt['status'] = 'Good'

result_list.append(dt)

# su1-14 사용자 shell 점검
dt = {}
result = 0
dt['SUV'] = 'SU1-14'
nopass = []
last = 0

cmd = os.popen("cat /etc/shadow").read().splitlines()
cmd1 = os.popen("cat /etc/passwd").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 shadow 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
if cmd1 == []:
    dt['value'] = '/etc에 passwd 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
for x in cmd:
    y = x.split(":")
    if y[1] == '*' or y[1] == '!!':
        nopass.append(y[0])
for x in cmd1:
    for count in nopass:
        y = x.split(":")
        if x[0] == count:
            if y[6] == "/bin/false" or y[6] == "/sbin/nologin":
                if x.startswith('#'):
                    result = 400
                else:
                    pass
            else:
                last += 1

if last == 0:
    dt['value'] = '모든 계정의 쉘을 수정했습니다.'
    dt['status'] = 'Good'
else:
    dt['value'] = '점검하지 않은 계정이 존제합니다.'
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

# su1-15 Session Timeout 설정
dt = {}
result = 0
code = 0
dt['SUV'] = 'SU1-15'

cmd = os.popen('echo $0').read()
cmd1 = os.popen("cat /etc/profile").read().splitlines()
cmd2 = os.popen("cat /etc/csh.login").read().splitlines()
cmd3 = os.popen("cat /etc/csh.cshrc").read().splitlines()

if 'sh' in cmd or 'ksh' in cmd or 'bash' in cmd:
    code = 1
elif 'csh' in cmd:
    code = 2

if cmd1 != [] and code == 1:
    for x in cmd1:
        if 'TMOUT' in x:
            numbers = re.findall(r'\d+', x)
            intnumbers = list(map(int, numbers))
            if intnumbers == []:
                result = 401
                break
            intnumber = intnumbers.pop(0)
            if intnumber <= 600:
                if x.startswith('#'):
                    result = 400
                else:
                    result = 2
                    break
            elif intnumbers == 0:
                pass
            else:
                dt['value'] = (
                    'Session timeout이 {}분으로 설정되어 있습니다.').format(int(intnumber / 60))
                dt['status'] = 'Weak'
                result += 1
                break

elif cmd2 != [] and code == 2:
    for x in cmd2:
        if 'set autologout' in x:
            numbers = re.findall(r'\d+', x)
            intnumbers = list(map(int, numbers))
            if intnumbers == []:
                result = 401
                break
            intnumber = intnumbers.pop()
            if intnumber <= 10:
                if x.startswith('#'):
                    result = 400
                else:
                    result = 2
                    break
            dt['value'] = (
                'Session timeout이 {}분으로 설정되어 있습니다.').format(intnumber)
            dt['status'] = 'Weak'
            result += 1
            break

elif cmd3 != [] and code == 2:
    code = 3
    for x in cmd3:
        if 'set autologout' in x:
            numbers = re.findall(r'\d+', x)
            intnumbers = list(map(int, numbers))
            if intnumbers == []:
                result = 401
                break
            intnumber = intnumbers.pop()
            if intnumbers <= 10:
                if x.startswith('#'):
                    result = 400
                else:
                    result = 2
                    break
            else:
                dt['value'] = (
                    'Session timeout이 {}분으로 설정되어 있습니다.').format(intnumber)
                dt['status'] = 'Weak'
                result += 1
                break

else:
    if code == 1:
        dt['value'] = '/etc에 profile 파일이 존재하지 않습니다.'
        dt['status'] = 'Weak'
    elif code == 2:
        dt['value'] = '/etc에 csh.login 파일이 존재하지 않습니다.'
        dt['status'] = 'Weak'
    elif code == 3:
        dt['value'] = '/etc에 csh.cshrc 파일이 존재하지 않습니다.'
        dt['status'] = 'Weak'

if result == 0:
    dt['value'] = 'Session timeout 설정이 존재하지 않습니다.'
    dt['status'] = 'Weak'

if result == 2:
    dt['value'] = 'Session timeout이 정상적으로 설정되었습니다.'
    dt['status'] = 'Good'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'

if result == 401:
    dt['value'] = 'export TMOUT만 설정했습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# su1-17 최근 패스워드 기억 설정
dt = {}
result = 0
code = 0
dt['SUV'] = 'SU1-17'
cmd1 = os.popen("cat /etc/pam.d/system-auth").read().splitlines()
if cmd1 != []:
    for x in cmd1:
        if "password" in x:
            if "sufficient" in x:
                if "remember" in x:
                    y = x.split("remember")
                    numbers = re.findall(r'\d+', y[1])
                    intnumbers = list(map(int, numbers))
                    intnumber = intnumbers.pop()

                    if x.startswith('#'):
                        result = 400
                    else:
                        if intnumber >= 5:
                            dt['value'] = (x)
                            dt['status'] = 'Good'
                            result += 1
                            goodacount += 1
                            break
                        else:
                            dt['value'] = 'remember값이 5미만입니다.'
                            dt['status'] = 'Weak'
                            result += 1
                            break
else:
    dt['value'] = '/etc/pam.d에 system-auth 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'

if result == 0:
    dt['value'] = 'remember 설정이 존재하지 않습니다.'
    dt['status'] = 'Weak'

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'

result_list.append(dt)

# su1-16 취약한 패스워드 점검
adt = {}
result = 0
adt['SUV'] = 'SU1-16'
if goodacount == 7:
    adt['value'] = '패스워드가 완벽하게 처리되어있습니다.'
    adt['status'] = 'Good'
else:
    adt['value'] = '{}개의 패스워드 취약점이 있습니다.'.format(7 - goodacount)
    adt['status'] = 'Weak'

result_list.append(adt)
result_list.append(dt)

# su1-18
dt = {}
result = 0
root = 0
startcomments = []
endcomments = []
count = 0
i = 0
version = ''

dt['SUV'] = 'SU1-18'
cmd = os.popen("find / -type d  -name 'apache-tomcat*'").read().splitlines()
if cmd == []:
    dt['value'] = 'apache-tomcat이 설치되지 않았습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        y = x.split("/apache-tomcat-")
        root = y[0]
        version = y[1]
    if root != 0:
        cmd = os.popen("cat " + root + "/" + "apache-tomcat-" +
                       version + "/conf/tomcat-users.xml").read().splitlines()
        for x in cmd:
            if "<!--" == x:
                startcomments.append(i)
            if "-->" == x:
                endcomments.append(i)
            if '<user username="tomcat" password="<must-be-changed>" roles="tomcat"/>' in y or '<user username="both" password="<must-be-changed>" roles="tomcat,role1"/>' in y or '<user username="role1" password="<must-be-changed>" roles="role1"/>' in y:
                dt['value'] = '기본 계정이 존재합니다.'
                dt['status'] = 'Weak'
                break
            else:
                dt['value'] = '기본 계정이 존재하지 않습니다.'
                dt['status'] = 'Good'
            i += 1
        for x in startcomments:
            for y in cmd[x:endcomments[count] + 1]:
                if '<user username="tomcat" password="<must-be-changed>" roles="tomcat"/>' in y or '<user username="both" password="<must-be-changed>" roles="tomcat,role1"/>' in y or '<user username="role1" password="<must-be-changed>" roles="role1"/>' in y:
                    dt['value'] = '기본 계정이 존재하지 않습니다.'
                    dt['status'] = 'Good'
            count += 1

result_list.append(dt)

# su1-19
dt = {}
result = 0
dt['SUV'] = 'SU1-19'

cmd = os.popen("cat /etc/shadow").read().splitlines()
if cmd == []:
    dt['value'] = '/etc에 shadow 파일이 존재하지 않습니다.'
    dt['status'] = 'Weak'
    result = 404
else:
    for x in cmd:
        try:
            y = "".join(x).split(':')
            numbers = re.findall(r'\d+', y[1])
            intnumbers = list(map(int, numbers))
            intnumber = intnumbers.pop(0)
            if intnumber >= 5:
                if x.startswith('#'):
                    result = 400
                else:
                    dt['value'] = '모든 패스워드 알고리즘이 안전합니다.'
                    dt['status'] = 'Good'
            else:
                dt['value'] = ('{}에서 패스워드 취약점이 발견되었습니다.').format(x)
                dt['status'] = 'Weak'
                break
        except:
            dt['value'] = ('{}에서 패스워드 취약점이 발견되었습니다.').format(x)
            dt['status'] = 'Weak'
            break

if result == 400:
    dt['value'] = '주석처리가 되어있습니다.'
    dt['status'] = 'Weak'
result_list.append(dt)

print(result_list)