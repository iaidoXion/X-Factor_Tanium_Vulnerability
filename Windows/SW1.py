"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
# -*- coding: utf-8 -*-
import os
from datetime import datetime
import logging
import sys
result = []
result_list = []
def do_stuff():
    os.system('secedit /export /cfg .\\test.inf')
    text = open('.\\test.inf', 'rb')
    y = text.read()
    x = y.decode('utf-16')
    text.close()
    result = x.splitlines()
    status = ""
    for x in result :
        dt = {}
        if 'NewAdministratorName' in x: #로컬 정책 > 보안 옵션 > 계정:Administrator 계정 이름 바꾸기(1번)
            try :
                logging.info('{} : !!!!!!SWV1-01 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('"')[1]
                if value == "Administrator" :
                    status=  "Weak"
                else:
                    status = "Good"
                dt['SWV'] = 'SW1-01'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-01'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = str(e).decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-01 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'EnableGuestAccount' in x: #로컬 정책 > 보안 옵션 > 계정:Guest 계정 상태(2번)
            try :
                logging.info('{} : !!!!!!SWV1-02 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('=')[1].strip()
                if value == str(0) :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-02'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-02'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = str(e).decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-02 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'LockoutBadCount' in x : #계정 정책 > 계정 잠금 정책 > 계정 잠금 임계값(4번)
            try :
                logging.info('{} : !!!!!!SWV1-04 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('=')[1].strip()
                if int(value) <= 5 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-04'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = str(e).decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-04'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = str(e).decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-04 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'ClearTextPassword' in x : #계정 정책 > 암호 정책 > 해독 가능한 암호화를 사용하여 암호 저장(5번)
            try :
                logging.info('{} : !!!!!!SWV1-05 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = int(x.strip().split('=')[1])
                if value == 0 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-05'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-05'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = str(e).decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-05 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous' in x : #로컬 정책 > 보안 옵션 > 네트워크 액세스:Everyone 사용 권한을 익명 사용자에게 적용(7번)
            try :
                logging.info('{} : !!!!!!SWV1-07 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = int(x.strip().split(',')[1])
                if value == 0 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-07'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-07'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = str(e).decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-07 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'LockoutDuration' in x : # 계정 잠금 기간 ("8번")
            try :
                logging.info('{} : !!!!!!SWV1-08 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('=')[1].strip()
                if int(value) >= 60 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-08'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-08'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-08 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'PasswordComplexity' in x : #암호는 복장섭을 만족해야 함 ('9번')
            try :
                logging.info('{} : !!!!!!SWV1-09 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('=')[1].strip()
                if int(value) == 1 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-09'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-09'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-09 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'MinimumPasswordLength' in x: #암호 길이 8문자 이상 설정('10번')
            try :
                logging.info('{} : !!!!!!SWV1-10 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                if 'MinimumPasswordLengthAudit' in x :
                    continue
                value = x.strip().split('=')[1].strip()
                if int(value) >= 8 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-10'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-10'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-10 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'MaximumPasswordAge' in x : #계정 정책 > 암호 정책 > 최대 암호 사용 기간(11번)
            try :
                logging.info('{} : !!!!!!SWV1-11 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                if 'CurrentControlSet' in x :
                    continue
                value = x.strip().split('=')[1].strip()
                if int(value) <= 90 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-11'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-11'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-11 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'MinimumPasswordAge' in x : #MinimumPasswordAge = 0  : 계정 정책 > 암호 정책 > 최소 암호 사용 기간(12번)
            try :
                logging.info('{} : !!!!!!SWV1-12 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.split('=')[1].strip()
                if int(value) > 0 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-12'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-12'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-12 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName' in x : #로컬 정책 > 보안 옵션 > 대화형 로그온:마지막 로그인 사용자 이름 표시 안함.(13번)
            try :
                logging.info('{} : !!!!!!SWV1-13 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split(',')[1].strip()
                if int(value) == 0 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-13'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = x.decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-13'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-13 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'SeInteractiveLogonRight' in x : #(14번)
            try :
                logging.info('{} : !!!!!!SWV1-14 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-14'
                value = x.split('=')
                del value[0]
                for i in range(len(value)) :
                    value[i] = value[i].strip()
                if ',' in value[0] :
                    value = value[0].replace(' ', '').split(',')
                    if '*S-1-5-32-544' in value :
                        del value[value.index('*S-1-5-32-544')]
                    if '*S-1-5-17' in value :
                        del value[value.index('*S-1-5-17')]
                else :
                    if '*S-1-5-32-544' in value :
                        del value[value.index('*S-1-5-32-544')]
                    if '*S-1-5-17' in value :
                        del value[value.index('*S-1-5-17')]
                if len(value) != 0 :
                    dt['status'] = "Weak"
                    dt['value'] = value
                else :
                    dt['status'] = "Good"
                    dt['value'] = 'None'
                if sys.version_info[0] == 2 :
                    dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-04'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-14 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'LSAAnonymousNameLookup' in x : #MinimumPasswordAge = 0  : 계정 정책 > 암호 정책 > 최소 암호 사용 기간(15번)
            try :
                logging.info('{} : !!!!!!SWV1-15 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('=')[1].strip()
                if int(value) == 0 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-15'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-15'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-15 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'PasswordHistorySize' in x : #MinimumPasswordAge = 0  : 계정 정책 > 암호 정책 > 최근 암호 기억(16번)
            try :
                logging.info('{} : !!!!!!SWV1-16 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split('=')[1].strip()
                if int(value) >= 12 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-16'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-16'
                dt['status'] = 'error'
                dt['value'] = str(e)
                if sys.version_info[0] == 2 :
                    dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            logging.info('{} : !!!!!!SWV1-16 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' in x : #로컬 정책 > 보안 옵션 > 계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한(17번)
            try :
                logging.info('{} : !!!!!!SWV1-17 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                value = x.strip().split(',')[1].strip()
                if int(value) == 1 :
                    status = "Good"
                else:
                    status=  "Weak"
                dt['SWV'] = 'SW1-17'
                dt['status'] = status
                dt['value'] = x
                if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-17'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-17 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'SeRemoteInteractiveLogonRight' in x :
            try :
                logging.info('{} : !!!!!!SWV1-18 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-18'
                cmd = os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" | find /I "fDenyTSConnections"').read().split('REG_DWORD')
                if int(cmd[1].strip()[2:]) > 0 :
                    dt['value'] = '원격터미널 사용안함'
                    status = "Good"
                else :
                    value = x.strip().split('=')[1].strip()
                    Remote_group = []
                    if ',' in value :
                        value = value.split(',')
                    else :
                        value = [value]
                    if '*S-1-5-32-544' in value :
                        del value[value.index('*S-1-5-32-544')]
                    if '*S-1-5-32-555' in value :
                        cmd = os.popen('net localgroup "Remote Desktop Users"').readlines()
                        if '명령을 잘 실행했습니다.\n' not in cmd :
                            Remote_group = []
                        else :
                            del cmd[0:6]
                            del cmd[cmd.index('명령을 잘 실행했습니다.\n')]
                            del cmd[cmd.index('\n')]
                            Remote_group = cmd
                    if len(value) == 0 and len(Remote_group) == 0:
                        dt['value'] = 'Remote terminal is in use and no logon allowed groups and accounts are specified.'
                        status = "Weak"
                    else :
                        dt['value'] = 'You are using a remote terminal, and the logon permission group and accounts are {}, and the logon permission group has {}.'.format(value, Remote_group)
                        status = "Good"
                dt['status'] = status
                if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            except Exception as e:
                logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
                dt['SWV'] = 'SW1-18'
                dt['status'] = 'error'
                dt['value'] = str(e)
            logging.info('{} : !!!!!!SWV1-18 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if 'status' in dt :
            result_list.append(dt)
    
    # [SW1-03]
    dt = {}
    try :
        logging.info('{} : !!!!!!SWV1-03 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        dt['SWV'] = 'SW1-03'
        nline = []
        account_list = []
        result_dt ={}
        cmd = os.popen('net user | find /v "accounts for" ').readlines()
        for line in cmd :
            if '사용자 계정' in line :
                continue
            elif ('-------------------------') in line :
                continue
            elif ('명령을 잘 실행했습니다.') in line :
                continue
            elif ('하나 이상의') in line :
                continue
            nline.append(line.split('\n')[0].split('  '))
        nline = filter(None, nline)
        for i in nline :
            i = filter(len, i)
            for j in i :
                account_list.append(j.strip())
        account_list = [s for s in account_list if s]
        result_dt['unnecessary account'] = account_list
        # for i in account_list :
        if 'Administrator' in account_list :
            del account_list[account_list.index('Administrator')]
        if 'user' in account_list :
            del account_list[account_list.index('user')]
        if '관리자' in account_list :
            del account_list[account_list.index('관리자')]
        if len(account_list) != 0 :
            status = "Weak"
        else :
            status = "Good"
        dt['status'] = status
        dt['value'] = "{} Set to vulnerable if there are others except Administrator, user, and administrator".format(account_list)
        if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)    
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        dt['SWV'] = 'SW1-03'
        dt['status'] = 'error'
        dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV1-03 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    result_list.append(dt)

    #1-06
    dt = {}
    try : 
        logging.info('{} : !!!!!!SWV1-06 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        dt['SWV'] = 'SW1-06'
        cmd = os.popen('net localgroup administrators | find /v "명령을 잘 실행"').readlines()
        nline = []
        result = []
        for line in cmd :
            nline.append(line.split('\n')[0])
        for i in nline :
            if '별칭' in i :
                continue
            elif '설명' in i :
                continue
            elif '구성원' in i :
                continue
            elif '----------------' in i :
                continue
            result.append(i)
        result = [s for s in result if s]
        if 'Administrator' in result :
            del result[result.index('Administrator')]
        if len(result) != 0 :
            dt['status'] = 'Weak'
        else :
            dt['status'] = 'Good'
        dt['value'] = result
        if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
    
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        dt['SWV'] = 'SW1-06'
        dt['status'] = 'error'
        dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV1-06 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    result_list.append(dt)
    #[SW1-19]
    net_list = []
    dt = {}
    try :
        logging.info('{} : !!!!!!SWV1-19 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        dt['SWV'] = 'SW1-19'
        cmd = os.popen('net accounts').readlines()
        cmd = [s for s in cmd if s]
        dt['status'] = 'Good'
        if int(cmd[1].split(':')[1].strip()) == 0 :
            dt['status'] = 'Weak'
            net_list.append(cmd[1])
        if int(cmd[2].split(':')[1].strip()) > 90 :
            dt['status'] = 'Weak'
            net_list.append(cmd[2])
        if int(cmd[3].split(':')[1].strip()) < 8 :
            dt['status'] = 'Weak'
            net_list.append(cmd[3])
        if cmd[4].split(':')[1].strip() == '없음' :
            dt['status'] = 'Weak'
            net_list.append(cmd[4])
        elif int(cmd[4].split(':')[1].strip()) < 12 :
            dt['status'] = 'Weak'
            net_list.append(cmd[4])
            
        if len(net_list) == 0 :
            dt['value'] = 'Good'
        else :
            dt['value'] = net_list
        if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        dt['SWV'] = 'SW1-19'
        dt['status'] = 'error'
        dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV1-19 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    result_list.append(dt)
    
    # [SW1-20]
    try :
        logging.info('{} : !!!!!!SWV1-20 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        result = []
        final = []
        result_dt ={}
        root = []
        dt = {}
        dt['SWV'] = 'SW1-20'
        tomcat_root = []
        tomcat = []
        start = False
        status = ''
        cmd = os.popen('path').read().strip('PATH=').split(";")
        bool = "False"
        for i in cmd :
            if 'Tomcat' in i :
                root.append(i)
                bool = "True"
            else :
                result_dt['value'] = "Tomcat does not exist in the environment variable or is not installed."
                status = 'Good'
        if bool == "True" :
            for i in root :
                if '\\' in i or '/' in i:
                    if i.rfind('bin') :
                        tomcat_root.append(i[:i.rfind('bin')])
                    else :
                        tomcat_root.append(i.strip())
            try :
                root = ""
                for i in tomcat_root :
                    for (path, dir, files) in os.walk(i):
                        if "tomcat-users.xml" in files :
                            root = path + '\\' +'tomcat-users.xml'
                            print(root)
                            break
                text = open(root, 'rb')
                y = text.read()
                x = y.decode('utf-8')
                text.close()
                split_line = x.splitlines()
                tomcat_root = []
                for j in split_line :
                    if start == True:
                        tomcat.append(j)
                    if '<!--' in j :
                        tomcat.append(j)
                        start = True
                    elif '-->' in j :
                        tomcat.append(j)
                        tomcat_root.append(tomcat) #주석처리를 위한 List
                        start = False
                        tomcat = []

                    if 'rolename' in j :
                        result.append(j)
                for v in result:
                    if v not in final:
                        final.append(v)
                        if 'tomcat' in v or 'role1' in v :
                            status = "Week"
                result_dt['value'] = final
                
                # 주석처리 검사
                for i in tomcat_root :
                    for j in i :
                        if 'rolename' in j :
                            if 'tomcat' in j or  'role1' in j :
                                status = "Good"
                                result_dt['value'] = "It's annotated."
            except :
                result_dt['value'] = "Failed to find tomcat-users.xml."
                status = "Good"
        dt['status'] = status
        dt['value'] = result_dt['value']
        if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
        why = {}
        why['SWV'] = 'SW1-20'
        why['status'] = status
        why['value'] = result_dt['value']
        if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(why['value']) is list :
                        for i in why['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        why['value'] = decode_list
                    else :
                        why['value'] = why['value'].decode('utf-8')
                    tanium.results.add(why)
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        why = {}
        why['SWV'] = 'SW1-20'
        why['status'] = 'error'
        why['value'] = str(e)
    logging.info('{} : !!!!!!SWV1-20 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    result_list.append(why)
    
    count = 0
    for i in result_list :
        if i['SWV'] == "SW1-08" :
            break
        count = count + 1
        if count == len(result_list) :
            logging.info('{} : !!!!!!SWV1-08 is Not Enabled!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            logging.info('{} : !!!!!!SWV1-08 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dt['SWV'] = 'SW1-08'
            dt['status'] = "Weak"
            if sys.version_info[0] == 2 :
                    decode_list = []
                    if type(dt['value']) is list :
                        for i in dt['value'] :
                            deocde_list.append(i.decode('utf-8'))
                        dt['value'] = decode_list
                    else :
                        dt['value'] = dt['value'].decode('utf-8')
                    tanium.results.add(dt)
            result_list.append(dt)
            logging.info('{} : !!!!!!SWV1-08 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    from pprint import pprint
    pprint(result_list)
do_stuff()
#     if sys.version_info[0] == 3 :
#         tanium.results.add(result_list)
# try:
# 	do_stuff()
# except Exception as e:
# 	tanium.results.add("ERROR executing sensor : {}".format(e))