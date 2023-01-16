"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
# -*- coding: utf-8 -*-
import subprocess
import os
import re
from datetime import datetime
import logging
import sys
try :
    import winreg as reg
except ImportError:
    import _winreg as reg
import xml.etree.ElementTree as ET
tanium_list = []
print(sys.version_info[0])
def SW2() :
    count = 0
    dt_list = []
    text = []
    text_list = {}
    result=[]
    IIS_bool="False"
    cmd = os.popen("sc query state= all").readlines()
    dt = {}
    system_list = []
    for line in cmd :
        nline = line.split('\n')[0]
        if "SERVICE_NAME" in nline :
            dt['SERVICE_NAME'] = nline.split(':')[1].strip()
        elif "DISPLAY_NAME" in nline :
            dt['DISPLAY_NAME'] = nline.split(':')[1].strip()
        elif "종류" in nline :
            dt["TYPE"] = nline.split(':')[1].strip()
        elif "상태" in nline :
            dt['STATUS'] = nline.split(':')[1]
            system_list.append(dt)
            dt = {}
    try :
        os.chdir("\\Windows\\System32\\inetsrv")
        cmd = subprocess.check_output("appcmd list config /xml").decode('utf-8')
        for i in cmd.split('>') :
            i = i + ">"
            x = re.sub(r'\n', '', i)
            y = re.sub(r'\r', '', x)
            dt_list.append(y.strip())
        for i in dt_list :
            if "<CONFIG " in i :
                text.append(i)
                continue
            elif "<?xml" in i :
                continue
            elif "<appcmd" in i :
                continue
            text.append(i)
            if "</CONFIG" in i :
                text_list["index"] = count
                text_list['text'] = text
            else :
                continue
            result.append(text_list)
            text = []
            text_list = {}
            count = count + 1
    except Exception as e:
        IIS_bool = "True"
    # [SW2-01]
    error_dt = {}
    test_list = []
    try :
        logging.info('{} : !!!!!!SWV2-01 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        cmd = os.popen('net share | find /v "$" | find /v "명령"').readlines()
        error_dt['SWV'] = 'SW2-01'
        count = 0
        for line in cmd :
            nline = line.split('\n')[0]
            if len(nline.strip().split(':')) == 2 :
                test_list.append(nline.strip().split(':')[1])
        for line in test_list :
            cmd = os.popen('icacls "' + line + '" | findstr /i "everyone" 2>nul').read()
            if "Everyone" in cmd :
                count = count + 1
        sw1 = "Everyone 권한의 공유가 {}개 있습니다".format(count) 
        error_dt['value'] = sw1
        if count == 0 :
            error_dt['status'] = "Good" 
        else :
            error_dt['status'] = "Weak" 
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['SWV'] = 'SW2-01'
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-01 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-02]
    dt = {}
    error_dt = {}
    error_dt['SWV'] = 'SW2-02'
    count = 0
    try :
        logging.info('{} : !!!!!!SWV2-02 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        cmd = os.popen('net share').read().splitlines()
        for i in cmd:
            if '기본 공유' in i :
                dt['기본공유 존재여부'] = i
            count = count + 1
            if count == len(cmd) :
                if '기본공유 존재여부' not in dt:
                    dt['기본공유 존재여부'] = 'Null'
        cmd = os.popen('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"').readlines()
        for i in cmd :
            if 'AutoShareServer' in i :
                dt['AutoShareServer'] = i.split('REG_DWORD')
                break
            else :
                dt['AutoShareServer'] = 'None'
        if dt['AutoShareServer'] == 'None' :
            if dt['기본공유 존재여부'] == 'Null' :
                error_dt['status'] = 'Good'
                error_dt['value'] = '기본공유가 존재하지 않습니다.'
            else :
                error_dt['status'] = 'Weak'
                error_dt['value'] = dt['기본공유 존재여부']
        else :
            if int(dt['AutoShareServer'][1].strip()[2:]) == 0 :
                if dt['기본공유 존재여부'] == 'Null' :
                    error_dt['status'] = 'Good'
                    error_dt['value'] = '기본공유가 존재하지 않습니다.'
                else :
                    error_dt['status'] = 'Weak'
                    error_dt['value'] = dt['기본공유 존재여부']
            else :
                error_dt['status'] = 'Weak'
                error_dt['value'] = dt['기본공유 존재여부']
            error_dt['status'] = 'Weak'
            error_dt['value'] = dt['AutoShareServer']
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-02 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-03]
    count = 0
    error_dt = {}
    error_list = []
    try :    
        logging.info('{} : !!!!!!SWV2-03 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        for i in system_list :
            if i['DISPLAY_NAME'] == "Alerter" :
                count = count + 1
                error_list.append(i['DISPLAY_NAME'])
            elif i['DISPLAY_NAME'] == "Clipbook" :
                count = count + 1
                error_list.append(i['DISPLAY_NAME'])
            elif i['DISPLAY_NAME'] == "Messenger" :
                count = count + 1
                error_list.append(i['DISPLAY_NAME'])
        error_dt['SWV'] = 'SW2-03'
        if count > 0 :
            error_dt['value'] = error_list
            error_dt['status'] = "Weak"
        else :
            error_dt['value'] = 'Alerter, Clipbook, Messenger 서비스가 구동중이지 않습니다'
            error_dt['status'] = "Good"
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['SWV'] = 'SW2-03'
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-03 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-04]
    error_dt = {}
    error_dt['SWV'] = 'SW2-04'
    error_list = []
    try :
        logging.info('{} : !!!!!!SWV2-04 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        for i in system_list:
            if i['DISPLAY_NAME'] == "IIS Admin Service":
                if 'RUNNING' in i['STATUS']:
                    error_list.append(i['DISPLAY_NAME'])
            elif i['DISPLAY_NAME'] == "World Wide Web Publishing Service" :
                if 'RUNNING' in i['STATUS']:
                    error_list.append(i['DISPLAY_NAME'])
            elif i['DISPLAY_NAME'] == "World Wide Web Publishing 서비스" :
                if 'RUNNING' in i['STATUS']:
                    error_list.append(i['DISPLAY_NAME'])
        if len(error_list) == 0 :
            error_dt['status'] = "Good"
            error_dt['value'] = 'IIS가 설치되어있지않거나 서비스를 실행중이지 않음'
        else :
            error_dt['status'] = "Weak"
            error_dt['value'] = error_list
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['SWV'] = 'SW2-04'
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-04 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-05]
    error_dt = {}
    error_list = []
    try :
        logging.info('{} : !!!!!!SWV2-05 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if IIS_bool == "True" :
            error_dt['SWV'] = 'SW2-05'
            error_dt['status'] = 'Good'
            error_dt['value'] = 'IIS가 설치되어있지않음'
        else:
            for i in result :
                for j in i['text'] :
                    if 'system.webServer/directoryBrowse' in j :
                        if len(i['text']) > 1 :
                            for y in i['text'] :
                                error_dt = {}
                                if "directoryBrowse enabled=" in y :
                                    error_dt['value'] = y.split(' ')[1]
                                    if y.split(' ')[1] == 'enabled="true"' :
                                        error_dt['status'] = 'Weak'
                                        error_dt['value'] = y.split(' ')[1]
                                        break
                                    else :
                                        error_dt['status'] = 'Good'
                                        error_dt['value'] = y.split(' ')[1]
                                        break
            error_dt['SWV'] = 'SW2-05'
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['SWV'] = 'SW2-05'
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-05 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-06]
    error_dt = {}
    error_list = []
    count = 0
    error_dt['SWV'] = 'SW2-06'
    try :
        logging.info('{} : !!!!!!SWV2-06 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if IIS_bool == "True" :
            error_dt['value'] = 'IIS가 설치되어있지않음'
            error_dt['status'] = 'Good'
            # F(모든권한) / M(모든권한만 체크 안되어있음) / W(수정)
        elif IIS_bool == "False":
            cmd = os.popen('icacls C:\inetpub\*scripts* | find /i "Everyone"').readlines()
            if len(cmd) == 0 :
                error_list.append('scripts 폴더가 없거나 Everyone 권한이 존재하지 않음')
            else :
                if 'F' in cmd[0].split('Everyone:')[1] or 'W' in cmd[0].split('Everyone:')[1] or 'M' in cmd[0].split('Everyone:')[1]:
                    error_list.append(cmd)
                    count = count + 1
                else : error_list.append(cmd)
            cmd = os.popen('icacls C:\inetpub\cgi-bin | find /i "Everyone"').readlines()
            if len(cmd) == 0 :
                error_list.append('cgi-bin에 scripts 폴더가 없거나 Everyone 권한이 존재하지 않음')
            else :
                if 'F' in cmd[0].split('Everyone:')[1] or 'W' in cmd[0].split('Everyone:')[1] or 'M' in cmd[0].split('Everyone:')[1]:
                    error_list.append(cmd)
                    count = count + 1
                else : error_list.append(cmd)
            cmd = os.popen('icacls %IIS_WEB_HOME%\*scripts* | find /i "Everyone"').readlines()
            if len(cmd) == 0 :
                error_list.append('IIS_WEB_HOME에 scripts 폴더가 없거나 Everyone 권한이 존재하지 않음')
            else :
                if 'F' in cmd[0].split('Everyone:')[1] or 'W' in cmd[0].split('Everyone:')[1] or 'M' in cmd[0].split('Everyone:')[1]:
                    error_list.append(cmd)
                    count = count + 1
                else : error_list.append(cmd)
            if count > 0 :
                error_dt['status'] = 'Weak'
                error_dt['value'] = error_list
            else :
                error_dt['status'] = 'Good'
                error_dt['value'] = error_list
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-06 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-07]
    error_dt = {}
    error_list = []
    try :
        logging.info('{} : !!!!!!SWV2-07 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if IIS_bool == "True" :
            error_dt['SWV'] = 'SW2-07'
            error_dt['value'] = 'IIS가 설치되어있지않음'
            error_dt['status'] = 'Good'
        elif IIS_bool == "False":
            for i in result :
                for j in i['text'] :
                    if 'system.webServer/asp' in j :
                        for y in i['text'] :
                            error_dt = {}
                            error_dt['SWV'] = 'SW2-07'
                            if 'ParentPaths' in y :
                                if y.split(' ')[1] == 'enableParentPaths="true">' :
                                    error_dt['value'] = y.split(' ')[1]
                                    error_dt['status'] = "Weak"
                                elif y.split(' ')[1] == 'enableParentPaths="false">' :
                                    error_dt['value'] = y.split(' ')[1]
                                    error_dt['status'] = "Good"
                                break
                            elif 'ParentPaths' not in y :
                                error_dt['value'] = 'value is null'
                                error_dt['status'] = "Good"
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['SWV'] = 'SW2-07'
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-07 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-08]
    error_dt = {}
    error_list = []
    try :
        logging.info('{} : !!!!!!SWV2-08 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        try :
            key = reg.HKEY_LOCAL_MACHINE
            key_value = "SOFTWARE\Microsoft\InetStp"
            open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            value, type1 = reg.QueryValueEx(open, "SetupString")
            error_dt['SWV'] = 'SW2-08'
            if float(value.split(' ')[1].strip()) < 7.0 :
                dir = os.listdir('C:\inetpub\iissamples')
                error_list.append('iissamples' + dir)
                dir = os.listdir('C:\winnt\help\iishelp')
                error_list.append('iishelp' + dir)
                dir = os.listdir('C:\program files\common')
                error_list.append('common' + dir)
                dir = os.listdir('C:\System32\inetsrv\iisadmpwd')
                error_list.append('iisadmpwd' + dir)
                error_dt['status'] = 'Weak'
                error_dt['value'] = error_list
            else :
                error_dt['value'] = 'IIS 7.0 이상 버전은 해당없음(' + value + ')'
                error_dt['status'] = 'Good'
        except :
            error_dt['SWV'] = 'SW2-08'
            error_dt['value'] = "IIS 설치되어있지않음"
            error_dt['status'] = 'Good'
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['SWV'] = 'SW2-08'
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-08 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-09]
    error_list = []
    error_dt = {}
    error_dt['SWV'] = 'SW2-09'
    try :
        logging.info('{} : !!!!!!SWV2-09 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if IIS_bool == "True" :
            error_dt['value'] = 'IIS가 설치되어있지않음'
            error_dt['status'] = 'Good'
        else:
            for i in result :
                for j in i['text'] :
                    if 'system.applicationHost/applicationPools' in j :
                        for y in i['text'] :
                            if 'processModel' in y :
                                if "LocalSystem" in y :
                                    split = y.split(' ')
                                    error_dt['status'] = 'Weak'
                                    error_dt['value'] = split[split.index('identityType="LocalSystem"')]
                                    break
                                else :
                                    error_dt['value'] = 'value is null'
                                    error_dt['status'] = 'Good'
                                    continue
                            else :
                                error_dt['value'] = 'value is null'
                                error_dt['status'] = 'Good'
                                if '</CONFIG>' in y:
                                    break
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-09 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-10]
    # 심볼릭링크, aliases = 바로가기
    count = 0
    error_dt = {}
    error_list = []
    path = ""
    real_path = ""
    error_dt['SWV'] = 'SW2-10'
    try :
        logging.info('{} : !!!!!!SWV2-10 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        if IIS_bool == "True" :
            error_dt['value'] = 'IIS가 설치되어있지않음'
            error_dt['status'] = 'Good'
        else:
            for i in result :
                for j in i['text'] :
                    if 'system.applicationHost/sites' in j :
                        for y in i['text'] :
                            if 'virtualDirectory path' in y :
                                path = y
            for i in path.split(' ') :
                if 'physicalPath' in i :
                    real_path = i.strip('physicalPath=').strip('"').replace('%SystemDrive%', "C:\\")
            dir = []
        try :
            dir = os.listdir(real_path)
            for i in dir :
                if '.lnk' in i :
                    error_dt['value'] = i
                    error_dt['status'] = 'Weak'
                count = count + 1
                if len(dir) == count :
                    if '바로가기 여부' not in i :
                        error_dt['value'] = 'None'
                        error_dt['status'] = 'Good'
        except :
            error_dt['value'] = "{} 경로가 올바르지 않습니다.".format(real_path)
            error_dt['status'] = 'Weak'
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-10 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    #[SW2-11]
    count = 0
    error_list = []
    error_dt = {}
    error_dt['SWV'] = 'SW2-11'
    limit_list = []
    try : 
        logging.info('{} : !!!!!!SWV2-11 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        BFL = True
        MEA = True
        if IIS_bool == "True" :
            error_dt['value'] = 'IIS가 설치되어있지않음'
            error_dt['status'] = 'Good'
        else:
            for i in result :
                for j in i['text'] :
                    if 'system.webServer/asp' in j :
                        for y in i['text'] :
                            if 'limits' in y :
                                if "bufferingLimit" in y or "maxRequestEntityAllowed" in y:
                                    split = y.split(' ')
                                    for z in split :
                                        if "bufferingLimit" in z :
                                            limit_list.append(z)
                                            BFL = False
                                        elif "maxRequestEntityAllowed" in z:
                                            limit_list.append(z)
                                            MEA = False
                                if BFL :
                                    error_list.append('bufferingLimit is NULL')
                                if MEA :
                                    error_list.append('maxRequestEntityAllowed is NULL')
                    if 'system.webServer/security/requestFiltering"' in j :
                        for y in i['text'] :
                            if 'requestLimits' in y :
                                if 'maxAllowedContentLength' in y :
                                    limit_list.append(y.replace('<', '').replace('>', ''))
                                    break
                                else :
                                    error_list.append('maxAllowedContentLength is NULL')
                                    break
        if len(limit_list) != 0 :
            error_dt['status'] = 'Good'
            error_dt['value'] = limit_list
        else :
            error_dt['status'] = 'Weak'
            error_dt['value'] = error_list
    except Exception as e:
        logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
        error_dt['status'] = 'error'
        error_dt['value'] = str(e)
    logging.info('{} : !!!!!!SWV2-11 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    tanium_list.append(error_dt)
    
    from pprint import pprint
    pprint(tanium_list)
SW2()
#     tanium.results.add(tanium_list)
# try :
#     SW2()
# except Exception as e :
#     tanium.results.add("Error : {}".format(e))