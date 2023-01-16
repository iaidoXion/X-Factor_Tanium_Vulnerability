"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
from datetime import datetime
import logging
from re import L
import os
error_list = []
# [SW3-01]
cmd_list = []
error_dict = {}
error_dict['SWV'] = 'SW3-01'
try :
    logging.info('{} : !!!!!!SWV3-01 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    sw1 = {}
    cmd=os.popen('systeminfo | find "KB"').read().splitlines() #핫픽스가 있는지 없는지 체크
    cmd_up=os.popen('sc query state=inactive |find "Windows Update"').read() #자동업데이트 되어있는지 (window update) 없으면 Null

    for i in cmd :
        cmd_list.append(i.split(':')[1].strip())
    sw1['HotFix Value'] = cmd_list
    if len(cmd_up) == 0 :
        sw1['WindowUpdate'] = 'Null'
    else :
        sw1['WindowUpdate'] = cmd_up.split(':')[1].strip()
        
    Bool_func = lambda x : True if 'KB' in x else False
    if [Bool_func(x) for x in sw1['HotFix Value']] :
        if "Windows Update" in sw1['WindowUpdate']:
            error_dict['status'] = 'Good'
            error_dict['value'] = sw1['WindowUpdate']
        else :
            error_dict['status'] = 'Weak'
            error_dict['value'] = '윈도우 자동 업데이트 실행 필요'
    else :
        error_dict['status'] = 'Weak'
        error_dict['value'] = "핫픽스 안깔려있음"
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-01 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)

# [SW3-02]
sw2 = []
error_dict = {}
error_dict['SWV'] = 'SW3-02'
try :
    logging.info('{} : !!!!!!SWV3-02 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen('sc query | findstr /i "ALYac Hauri V3 test Symantec AVG"').read().replace("DISPLAY_NAME:", "Running vaccine = ").splitlines()
    if len(cmd) == 0 :
        error_dict['status'] = 'Weak'
        error_dict['value'] = "백신명 {}, {}, {}, {}, {}, {}이 설치 및 구동되어있지않습니다.".format("ALYac", "Hauri", "V3", "test", "Symantec", "AVG")
    else:
        for i in cmd :
            if 'SERVICE_NAME' in i :
                continue
            sw2.append(i)

    Bool_func = lambda x : True if 'Running vaccine' in x else False
    if [Bool_func(x) for x in sw2]:
        if "Update" in sw2:
            error_dict['status'] = 'Good'
            error_dict['value'] = sw2
        else :
            error_dict['status'] = 'Weak'
            error_dict['value'] = "백신은 구동중이나 백신 업데이트가 꺼져있음."
    else:
        if 'status' not in error_dict :
            error_dict['status'] = 'Weak'
            error_dict['value'] = "백신 구동중이지 않음"
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-02 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)

# [SW3-03]
error_dict = {}
error_dict['SWV'] = 'SW3-03'
try :
    logging.info('{} : !!!!!!SWV3-03 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    os.system('secedit /export /cfg .\\test.inf')
    text = open('.\\test.inf', 'rb')
    y = text.read()
    x = y.decode('utf-16')

    text.close()
    sw3 = []
    result = x.splitlines()
    for x in result :
        if 'AuditLogonEvents' in x : # 설정값이 0이면 감사안함 = 취약 1이면 양호
            sw3.append(x)
        if 'AuditPrivilegeUse' in x:  # 설정값이 0이면 감사안함 = 취약 1이면 양호
            sw3.append(x)
        if 'AuditPolicyChange' in x:  # 설정값이 0이면 감사안함 = 취약 1이면 양호
            sw3.append(x)
        if 'AuditAccountManage' in x:  # 설정값이 0이면 감사안함 = 취약 1이면 양호
            sw3.append(x)
        if 'AuditDSAccess' in x:  # 설정값이 0이면 감사안함 = 취약 1이면 양호
            sw3.append(x)
        if 'AuditAccountLogon' in x:  # 설정값이 0이면 감사안함 = 취약 1이면 양호
            sw3.append(x)

    if ('AuditLogonEvents = 0' in sw3 or 'AuditPrivilegeUse = 0' in sw3  or 'AuditPolicyChange = 0' in sw3  or 'AuditAccountManage = 0' in sw3  or 'AuditDSAccess = 0' in sw3  or 'AuditAccountLogon = 0' in sw3 ):
        error_dict['status'] = 'Weak'
        error_dict['value'] = sw3
    else:
        error_dict['status'] = 'Good'
        error_dict['value'] = sw3
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-03 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)

    # [SW3-04]


# [SW3-05]
sw5 = []
error_dict = {}
error_dict['SWV'] = 'SW3-05'
try :
    logging.info('{} : !!!!!!SWV3-05 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen('sc query | find /i "Remote Registry"').read()
    if len(cmd) == 0 :
        error_dict['status'] = 'Weak'
        error_dict['value'] = 'Remote Registry Service is Not enabled'
    else :
        if 'Remote Registry' in cmd :
            error_dict['status'] = 'Good'
            error_dict['value'] = 'Remote Registry Service is enabled'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-05 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)

# [SW3-06]
dict ={}
error_dict = {}
error_dict['SWV'] = 'SW3-06'
sw6 = []
try :
    logging.info('{} : !!!!!!SWV3-06 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd_app=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application" | find /I "MaxSize"').readlines()[0].strip('\n')[4:].split('REG_DWORD')[1].strip()
    cmd_app_ret=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application" | find /I "Retention"').readlines()[0].strip('\n')[4:].split('REG_DWORD')[1].strip()

    cmd_sys=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System" | find /I "MaxSize"').readlines()[0].strip('\n')[4:].split('REG_DWORD')[1].strip()
    cmd_sys_ret=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System" | find /I "Retention"').readlines()[0].strip('\n')[4:].split('REG_DWORD')[1].strip()

    cmd_sec=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" | find /I "MaxSize"').readlines()[0].strip('\n')[4:].split('REG_DWORD')[1].strip()
    cmd_sec_ret=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" | find /I "Retention"').readlines()[0].strip('\n')[4:].split('REG_DWORD')[1].strip()

    #system
    dict['name'] = 'system'
    dict['size'] = cmd_sys
    dict['retention'] = cmd_sys_ret
    sw6.append(dict)
    dict ={}
    #security
    dict['name'] = 'security'
    dict['size'] = cmd_sec
    dict['retention'] = cmd_sec_ret
    sw6.append(dict)

    dict ={}
    #application
    dict['name'] = 'Application'
    dict['size'] = cmd_app
    dict['retention'] = cmd_app_ret
    sw6.append(dict)
    # MaxSize
    # 0xa00000 : 10,240KB
    # 20480

    # Retention
    # 0xffffffff : 로그가 꽉 차면 로그 보관, 이벤트를 덮어쓰지않음 / 이벤트를 덮어쓰지 않음
    # 0x0 : 필요한 경우 이벤트 덮어쓰기

    for i in sw6 :
        if i['name'] == 'system' :
            sw6SyM = i['size']
            sw6SyR = i['retention']
            i['size'] = int(i['size'],16)//1024
            i['retention'] = int(i['retention'], 16)
        if i['name'] == 'security' :
            sw6SeM = i['size']
            sw6SeR = i['retention']
            i['size'] = int(i['size'],16)//1024
            i['retention'] = int(i['retention'], 16)
        if i['name'] == 'Application' :
            sw6AM = i['size']
            sw6AR = i['retention']
            i['size'] = int(i['size'],16)//1024
            i['retention'] = int(i['retention'], 16)
    if int(sw6AM,16)//1024 < 10240 or int(sw6SyM,16)//1024 < 10240 or int(sw6SeM,16)//1024 < 10240 :
            error_dict['status'] = 'Weak'
            error_dict['value'] = sw6
    else:
        if int(sw6AR,16) > 90 or int(sw6SyR,16) > 90 or int(sw6SeR,16) > 90 :
            error_dict['status'] = 'Weak'
            error_dict['value'] = sw6
        else :
            error_dict['status'] = 'Good'
            error_dict['value'] = sw6
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-06 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)

#[SW3-07]
dict = {}
sw7 = []
error_dict = {}
error_dict['SWV'] = 'SW3-07'
try :
    logging.info('{} : !!!!!!SWV3-07 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen('cacls %systemroot%\system32\logfiles | find "Everyone"').read()
    if len(cmd) == 0 :
        cmd = 'logfiles Everyone 권한여부 is None'
    dict['name'] = 'logfile'
    dict['value'] = cmd
    sw7.append(dict)

    cmd=os.popen('cacls %systemroot%\system32\config | find "Everyone"').read()
    if len(cmd) == 0 :
        cmd = 'config Everyone 권한여부 is None'
    dict = {}
    dict['name'] = 'config'
    dict['value'] = cmd
    sw7.append(dict)
    if "Everyone" in sw7[0]['value'] or "Everyone" in sw7[0]['value']:
            error_dict['status'] = 'Weak'
            error_dict['value'] = sw7[0]['value']
    else:
        error_dict['status'] = 'Good'
        error_dict['value'] = sw7[0]['value']
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-07 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)
#[SW3-08]
sw8 = {}
error_dict = {}
error_dict['SWV'] = 'SW3-08'
try :
    logging.info('{} : !!!!!!SWV3-08 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen('sc query state=inactive |find "Windows Update"').read() #자동업데이트 되어있는지 (window update) 없으면 Null
    print(cmd)
    if len(cmd) == 0 :
        error_dict['status'] = 'Weak'
        error_dict['value'] = '자동 업데이트가 되어있지않습니다.'
    else :
        error_dict['status'] = 'Good'
        error_dict['value'] = cmd
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-08 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)

#[SW3-09]
sw9 = []
sw9_list = []
error_dict = {}
error_dict['SWV'] = 'SW3-09'
try :
    logging.info('{} : !!!!!!SWV3-09 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd_sys=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System" /v RestrictGuestAccess').read().strip().split(" ")[12]
    cmd_app=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application" /v RestrictGuestAccess').read().strip().split(" ")[12]
    cmd_sec=os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v RestrictGuestAccess').read().strip().split(" ")[12]
    sw9_list.append("SW9 Eventlog\System guest 권한여부 = "+cmd_sys)
    sw9_list.append("SW9 Eventlog\Application guest 권한여부 = "+cmd_app)
    sw9_list.append("SW9 Eventlog\Security guest 권한여부 = "+cmd_sec)
    if "SW9 Eventlog\System guest 권한여부 = 0x1" in sw9_list and "SW9 Eventlog\Application guest 권한여부 = 0x1" in sw9_list and "SW9 Eventlog\Security guest 권한여부 = 0x1" in sw9_list :
        error_dict['status'] = 'Good'
        error_dict['value'] = sw9_list
    else:
        error_dict['status'] = 'Weak'
        error_dict['value'] = sw9_list
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dict['status'] = 'error'
    error_dict['value'] = str(e)
logging.info('{} : !!!!!!SWV3-09 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
error_list.append(error_dict)
tanium.results.add(error_list)