"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
import subprocess
import os
import re
import logging
from datetime import datetime
try :
    import winreg as reg
except ImportError:
    import _winreg as reg
import xml.etree.ElementTree as ET
tanium_list = []
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
#[2-19]
count = 0
error_list = []
dt = {}
error_dt = {}    
error_dt['SWV'] = 'SW2-19'
try :
    logging.info('{} : !!!!!!SWV2-19 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    for i in system_list :
        if "Microsoft FTP Service" in i['DISPLAY_NAME'] :
            if 'STOPPED' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Good'
            elif 'PAUSED' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Good'
            else :
                error_dt['value'] = i
                error_dt['status'] = 'Weak'
            break
        else :
            if 'value' not in error_dt:
                error_dt['value'] = 'FTP 사용중이 아님'
                error_dt['status'] = 'Good'
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-19 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-20]
error_dt = {}
error_list = []
bool = "False"
auth_list = []
error_dt['SWV'] = 'SW2-20'
try :
    logging.info('{} : !!!!!!SWV2-20 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else:
        cmd = os.popen('echo %WINDIR%').read()
        root = cmd.strip() + '\\System32\\Inetsrv\\Config\\applicationHost.config'
        error_list = []
        if os.path.exists(root) :
            web_config = ET.parse(root)
            root = web_config.getroot()
            ftpServer = root.iter('system.ftpServer')
            try :
                for i in ftpServer :
                    authorization = i.iter('authorization')
                    for j in authorization :
                        access = j.iter('add')
                        for k in access :
                            auth_dt = {}
                            auth_dt['type'] = k.attrib['accessType']
                            auth_dt['users'] = k.attrib['users']
                            auth_list.append(auth_dt)
            except :
                error_dt['status'] = 'Good'
                error_dt['value'] = 'FTP Server를 이용중이지않음'
            if len(auth_list) == 0 :
                error_dt['status'] = 'Good'
                error_dt['value'] = '아무런 권한을 게시하지않음'
            else :
                for i in auth_list :
                    if i['type'] == 'Allow' :
                        if i['users'] == '*' :
                            error_dt['status'] = 'Weak'
                            error_dt['value'] = i
                            break
                        else :
                            error_dt['status'] = 'Good'
                            error_dt['value'] = i
    #     for i in result :
    #         for j in i['text'] :
    #             if 'system.ftpServer/security/authorization' in j :
    #                 for y in i['text'] :
                        
    #                     print(y)
    #                     if 'accessType="Allow"' in y :
    #                         for k in y.split() :
    #                             if 'users' in k :
    #                                 error_dt['value'] = k
    #                                 error_dt['status'] = "Weak"
    #                                 bool = 'True'
    #                                 break
    #                     else :
    #                         error_dt['value'] = 'FTP 권한 부여 규칙이 설정되지 않음'
    #                         error_dt['status'] = "Weak"
    #                     if bool == "True" :
    #                         break
    #             if 'value' not in error_dt :
    #                 error_dt['value'] = 'FTP가 설정되지 않음'
    #                 error_dt['status'] = "Weak"
    #                 continue
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-20 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-21]
error_dt = {}
error_list = []
error_dt['SWV'] = 'SW2-21'
try :
    logging.info('{} : !!!!!!SWV2-21 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else :
        for i in result :
            for j in i['text'] :
                if 'system.applicationHost/sites' in j :
                    for y in i['text'] :
                        if 'anonymousAuthentication' in y :
                            if 'enabled="true"' in y:
                                error_dt['value'] = y.strip('<').strip('/>').strip()
                                error_dt['status'] = "Weak"
                                break
                            error_dt['value'] = 'FTP 익명 연결 허용 사용안함'
                            error_dt['status'] = "Good"
                        else :
                            if 'value' not in error_dt:
                                error_dt['value'] = 'FTP 게시 안함'
                                error_dt['status'] = "Good"
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-21 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-22]
count = 0
for_count = 0
error_dt = {}
dt = {}
error_list = []
error_dt['SWV'] = 'SW2-22'
sec_dt = {}
value = ''
status = ''
try :
    logging.info('{} : !!!!!!SWV2-22 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else :
        cmd = os.popen('echo %WINDIR%').read()
        root = cmd.strip() + '\\System32\\Inetsrv\\Config\\applicationHost.config'
        error_list = []
        if os.path.exists(root) :
            web_config = ET.parse(root)
            root = web_config.getroot()
            ftpServer = root.iter('system.ftpServer')
            try :
                for i in ftpServer :
                    ipSecurity = i.iter('ipSecurity')
                    for j in ipSecurity :
                        if 'allowUnlisted' in j.attrib :
                            sec_dt['value'] = j.attrib['allowUnlisted']
                            ipAddress = j.iter('add')
                            for k in ipAddress :
                                if 'ipAddress' in k.attrib :
                                    status = 'Good'
                                    value = k.attrib
                                else :
                                    status = 'Weak'
                                    value = k.attrib
                        else :
                            status = 'Weak'
                            value = '특정 IP주소에 FTP 서버 접속 접근제어 설정 적용안함'
                        # auth_dt = {}
                        # auth_dt['type'] = k.attrib['accessType']
                        # auth_dt['users'] = k.attrib['users']
                        # auth_list.append(auth_dt)
            except :
                status = 'Weak'
                value = '특정 IP주소에 FTP 서버 접속 접근제어 설정 적용안함'
        error_dt['status'] = status
        error_dt['value'] = value
        # for i in result :
        #     for j in i['text'] :
        #         if 'system.ftpServer/security/ipSecurity' in j :
        #             for y in i['text'] :  
        #                 print(y)                   
        #                 if 'allowUnlisted' in y :
        #                     split = y.split(' ')
        #                     for z in split :
        #                         if 'allowUnlisted' in z :
        #                             dt['allowUnlisted'] = z.strip('>').strip('allowUnlisted=').strip('"')
        #                 if 'ipAddress' in y :
        #                     split = y.split(' ')
        #                     for z in split:
        #                         if 'ipAddress' in z:
        #                             dt['name'] = z
        #                         elif 'allowed' in z :
        #                             dt['allowed'] = z
        #                         count = count + 1
        #                         if count == len(split) :
        #                             if 'allowUnlisted' not in dt:     
        #                                 dt['allowUnlisted'] = 'true'
        #                             error_list.append(dt)
        #                             break
        #                 else :
        #                     dt['name'] = "ipAddress"
        #                     dt['value'] = "value is None"
        #                 for_count = for_count + 1
                        
        #                 if for_count == len(i['text']) and len(dt) == 0:
        #                     error_list.append(dt)
        #                     break
        # for i in error_list:
        #     if 'allowed' not in i or 'allowUnlisted' not in i :
        #         error_dt['value'] = error_list
        #         error_dt['status'] = 'Weak'
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-22 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-23]
error_dt = {}
error_dt['SWV'] = 'SW2-23'
reg_dict = {}
Secure_list = []
try :
    logging.info('{} : !!!!!!SWV2-23 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    os.chdir("\\Windows\\System32\\inetsrv")
    dns_server = os.popen('net start | find /I "DNS Server"').read()
    if len(dns_server) == 0 :
        error_dt['value'] = "DNS 서비스사용하지 않음"
        error_dt['status'] = 'Good'
        error_list.append(error_dt)
    else :
        try :
            key = reg.HKEY_LOCAL_MACHINE
            key_value = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DNS Server\\Zones"
            open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            for i in range(5000) :
                reg_dict = {}
                keyname = reg.EnumKey(open, i)
                varSubkey2 = "%s\\%s" % (key_value, keyname) 
                varKey2 = reg.OpenKey(key, varSubkey2, 0 , reg.KEY_ALL_ACCESS)
                value, type1 = reg.QueryValueEx(varKey2, "SecureSecondaries")
                reg_dict['SecureSecondaries'] = value
                if int(value) < 3 :
                    value, type1 = reg.QueryValueEx(varKey2, "SecondaryServers")
                    reg_dict['SecondaryServers'] = value
                Secure_list.append(reg_dict)
        except :
            if len(Secure_list) == 0 :
                error_dt['value'] = 'DNS Zone Transfer 차단 설정이 적용되지 않았거나 DNS가 구동중이지 않습니다.'
            else :
                for i in Secure_list :
                    if int(i['SecureSecondaries']) < 3 :
                        if 'SecondaryServers' in i :
                            error_dt['status'] = 'Good'
                            error_dt['value'] = i
                        else :
                            error_dt['status'] = 'Weak'
                            error_dt['value'] = i
                            break
                    else :
                        error_dt['status'] = 'Good'
                        error_dt['value'] = i
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-23 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

#[SW2-24]
count = 0
for_count = 0
error_dt = {}
dt = {}
error_list = []
error_dt['SWV'] = 'SW2-24'
try :
    logging.info('{} : !!!!!!SWV2-24 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else :
        for i in result :
            for j in i['text'] :
                if 'system.applicationHost/sites' in j :
                    for y in i['text'] :
                        if 'virtualDirectory path' in y :
                            if "/msadc" in y or "/MSADC" in y :
                                split = y.split(' ')
                                for z in split:
                                    if 'physicalPath=' in z :
                                        value = z
                                        status = 'Weak'
                                        break
                            else :
                                status = 'Good'
                                value = "/MSADC is None"
        if status == 'Good' :
            cmd = os.popen('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" | find /I "RDSServer.DataFactory"').read().splitlines()
            cmd2 = os.popen('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" | find /I "AdvancedDataFactory"').read().splitlines()
            cmd3 = os.popen('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" | find /I "VbBusObj.VbBusObjCls"').read().splitlines()
            registry = []
            if len(cmd) ==0 and len(cmd2) == 0 and len(cmd3) == 0 :
                value = cmd3
                status = 'Good'
            elif len(cmd) != 0 :
                registry.append("RDSServer.DataFactory is Avialiable")
                value = cmd
                status = 'Weak'
            elif len(cmd2) != 0 :
                registry.append("AdvancedDataFactory is Avialiable")
                value = cmd2
                status = 'Weak'
            elif len(cmd3) != 0 :
                registry.append("VbBusObj.VbBusObjCls is Avialiable")
                value = cmd3
                status = 'Weak'
        error_dt['value'] = value
        error_dt['status'] = status
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-24 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-25]
cmd = os.popen('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v MinorVersion').readlines()
nline = []
error_dt = {}
dt = {}
error_dt['SWV'] = 'SW2-25'
error_list = []
try :
    logging.info('{} : !!!!!!SWV2-25 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    for line in cmd :
        nline.append(line.split('\n')[0])
    nline = filter(None, nline)
    for i in nline :
        if 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' in i :
            continue
        dt['name'] = '최신 서비스팩'
        dt['value'] = i
    if int(dt['value'].split('REG_SZ')[1]) != 0 :
        error_dt['value'] = dt['value']
        error_dt['status'] = 'Weak'
    else :
        error_dt['value'] = dt['value']
        error_dt['status'] = 'Good'
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-25 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

#[SW2-26]chdir
error_dt = {}
error_dt['SWV'] = 'SW2-26'
try :
    logging.info('{} : !!!!!!SWV2-26 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('net start | find /I "Remote Desktop Services"').read().strip()
    if 'Remote Desktop Services' not in cmd :
        error_dt['value'] = '터미널 서비스 실행되고 있지않음'
        error_dt['status'] = 'Good'
    else :
        try :
            key = reg.HKEY_LOCAL_MACHINE
            key_value = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            value, type1 = reg.QueryValueEx(open, "MinEncryptionLevel")
            if value < 2 :
                error_dt['status'] = 'Weak'
                error_dt['value'] = '클라이언트 연결 암호화 수준 : {}'.format(value)
            else :
                error_dt['status'] = 'Good'
                error_dt['value'] = '클라이언트 연결 암호화 수준 : {}'.format(value)
        except :
            error_dt['status'] = 'Weak'
            error_dt['value'] = '클라이언트 연결 암호화 수준 설정을 사용하고 있지않음'
except Exception as e:
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-26 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-27]
count = 0
dt = {}
error_dt = {}
error_list = []
dt_list = []
error_dt['SWV'] = 'SW2-27'
try :
    logging.info('{} : !!!!!!SWV2-27 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else :
        for i in result :
            for j in i['text'] :
                if 'system.webServer/httpErrors' in j :
                    for y in i['text'] :
                        if 'statusCode' in y :
                            split = y.split(' ')
                            for z in split:
                                if 'statusCode' in z :
                                    dt_list.append(z.strip('statusCode=').strip('"'))
                                    dt['name'] = 'statusCode'
                                    dt['value'] = dt_list
                        count = count + 1
                        if count == len(i['text']) :
                            error_list.append(dt)
                            break
        if len(error_list) != 0 :
            error_dt['value'] = error_list
            error_dt['status'] = 'Good'
        else :
            error_dt['value'] = 'statusCode is Null'
            error_dt['status'] = 'Weak'
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-27 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-28]
count = 0
error_list = []
error_dt = {}    
error_dt['SWV'] = 'SW2-28'
try :
    logging.info('{} : !!!!!!SWV2-28 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    for i in system_list :
        if 'SNMP Service' in i['DISPLAY_NAME'] or 'SNMP 서비스' in i['DISPLAY_NAME'] :
            if i['STATUS'] == ' 1  STOPPED ' :
                error_dt['value'] = i
                error_dt['status'] = 'Good'
                break
            else :
                error_dt['value'] = i
                error_dt['status'] = 'Weak'
                break
        else :
            error_dt['value'] = 'SNMP 서비스 존재하지않음'  
            error_dt['status'] = 'Good'
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-28 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-29]
count = 0
error_list = []
error_dt = {}    
error_dt['SWV'] = 'SW2-29'
try :
    logging.info('{} : !!!!!!SWV2-29 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    for i in system_list :
        if 'SNMP Service' in i['DISPLAY_NAME'] or 'SNMP 서비스' in i['DISPLAY_NAME'] :
            if i['STATUS'] == ' 1  STOPPED ' :
                error_dt['value'] = i
                error_dt['status'] = 'Good'
                break
            else :
                cmd = os.popen('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"').read().splitlines()
                if len(cmd) == 0 :
                    error_dt['value'] = '레지스트리 존재하지 않음'
                    error_dt['status'] = 'Good'
                else :
                    cmd = [v for v in cmd if v]
                    for j in cmd :
                        if 'HKEY_LOCAL_MACHINE' in j :
                            continue
                        error_list.append(j.split('REG_DWORD')[0].strip())
                    if len(error_list) == 0 :
                        error_dt['value'] = '받아들인 커뮤니티 이름이 존재하지 않습니다'
                        error_dt['status'] = 'Good'
                        break
                    else :
                        for i in error_list :
                            count = count + 1
                            if 'public' in i.lower() or 'private' in i.lower() :
                                error_dt['value'] = i
                                error_dt['status'] = 'Weak'
                                break
                            elif count == len(error_list) :
                                error_dt['value'] = error_list
                                error_dt['status'] = 'Good'
                                break    
        else :
            if 'value' not in error_dt:
                error_dt['value'] = 'SNMP 서비스 존재하지않음' 
                error_dt['status'] = 'Good'
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-29 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-30]
cmd = os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" 2>&1').readlines()
nline = []
error_dt = {}
error_list = []
dt_list = []
error_dt['SWV'] = 'SW2-30'
try :
    logging.info('{} : !!!!!!SWV2-30 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if len(cmd) < 2 :
        error_dt['status'] = "Good"
        error_dt['value'] = "SNMP가 설치되어있지않음"
    else :
        for line in cmd :
            nline.append(line.split('\n')[0])
        nline = filter(None, nline)
        for i in nline :
            if 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' in i:
                continue
            dt_list.append(i.split('REG_SZ')[1].strip())
        if len(dt_list) == 0 :
            error_dt['status'] = "Weak"
            error_dt['value'] = "'모든 호스트로 SNMP 패킷 받아들이기' 설정되어있음"
        else :
            if '오류' in dt_list[0] :
                error_dt['status'] = "Good"
                error_dt['value'] = "SNMP가 설치되어있지않음"
            else:
                error_dt['status'] = "Good"
                error_dt['value'] = "'특정 호스트{}로 SNMP 패킷 받아들이기' 설정되어있음".format(dt_list)
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-30 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-31]
error_dt = {}
error_list = []
error_dt['SWV'] = 'SW2-31'
try :
    logging.info('{} : !!!!!!SWV2-31 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    os.chdir("\\Windows\\System32\\inetsrv")
    cmd = os.popen('net start | find /I "DNS Server"').read()
    if len(cmd) == 0 :
        error_dt['value'] = "DNS 서비스 사용하지 않음"
        error_dt['status'] = 'Good'
        error_list.append(error_dt)
    else :
        cmd = os.popen('reg query "HKLM\software\microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "AllowUpdate"').read().splitlines()
        for i in cmd :
            if '0x1' in i :
                error_dt['status'] = "Weak"
                error_dt['value'] = "DNS : {}".format(cmd)
            elif '0x0' in i :
                error_dt['status'] = "Good"
                error_dt['value'] = "DNS : {}".format(cmd)
        if 'status' not in error_dt :
            error_dt['value'] = "DNS 서비스 사용하지 않음"
            error_dt['status'] = 'Good'
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-31 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
tanium.results.add(tanium_list)