"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
import subprocess
import os
import re
import winreg as reg
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
try :
    import winreg as reg
except ImportError:
    import _winreg as reg
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
# [SW2-32]
count = 0
dt = {}
error_dt = {}
error_list = []
dt_list = []
value = ''
vul_dt = {}
file_list = []
error_dt['SWV'] = 'SW2-32'
try :
    logging.info('{} : !!!!!!SWV2-32 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
        error_list.append(error_dt)
    else :
        for i in result :
            error_list = []
            for j in i['text'] :
                if 'system.webServer/rewrite/outboundRules' in j :
                    for y in i['text'] :
                        count = count + 1
                        if "rule name" in y :
                            dt_list.append(y)
                        elif 'match' in y :
                            dt_list.append(y)
                        elif count == len(i['text']):
                            if len(dt_list) != 0 :
                                dt['http'] = dt_list
                elif 'system.applicationHost/site' in j :
                    for y in i['text'] :
                        if 'suppressDefaultBanner' in y :
                            dt['ftp'] = y
                        if 'ftp' not in dt :
                            dt['ftp'] = '배너차단 설정 안함'
                else :
                    if 'http' not in dt :
                        if '<virtualDirectory path="/" physicalPath=' in j :
                            root = j.split('physicalPath=')[1].replace('"', '').strip('/>').strip()
                            if '%SystemDrive%' in root :
                                cmd = os.popen('echo %SystemDrive%').read().strip()
                                root = root.replace('%SystemDrive%', str(cmd)) + '\\web.config'
                            try :
                                web_config = ET.parse(root)
                                root = web_config.getroot()
                                rewrite = root.iter('rewrite')
                                for rw in rewrite :
                                    match = rw.iter('match')
                                    for mt in match :
                                        value = mt.attrib
                            except :
                                value = ''
                        if len(value) == 0 :
                            vul_dt['http'] = 'http value is null'
                            vul_dt['hstatus'] = False
                        else :
                            vul_dt['http'] = value
                            vul_dt['hstatus'] = True
                    else :
                        vul_dt['http'] = dt['http']
                        vul_dt['hstatus'] = True
                    if 'ftp' not in dt:
                        vul_dt['ftp'] = 'ftp value is null'
                        vul_dt['fstatus'] = False
                    else :
                        if 'false' in dt['ftp'] :
                            vul_dt['ftp'] = dt['ftp']
                            vul_dt['fstatus'] = False
                        elif 'true' in dt['ftp'] :
                            vul_dt['ftp'] = dt['ftp']
                            vul_dt['fstatus'] = True
        try :
            path = "C:\\Windows\\System32\\inetsrv\\History\\"
            for f_name in os.listdir(f"{path}") :
                written_time = os.path.getctime(f"{path}{f_name}")
                file_list.append([f_name, written_time])
            file_list = [file for file in sorted(file_list, key=lambda x : x[1], reverse=True) if file[0].startswith('MetaBase')]
            history_xml_path = path + file_list[0][0]
            try :
                histroy_xml = ET.parse(history_xml_path)
                root = histroy_xml.getroot()
                for i in root[0] :
                    if 'IIsSmtpServer' in i.tag :
                        if 'ConnectResponse' in i.attrib:
                            vul_dt['sstatus'] = True
                            vul_dt['SMTP'] = i.attrib['ConnectResponse']
                    if 'SMTP' not in vul_dt :
                        vul_dt['sstatus'] = False
                        vul_dt['SMTP'] = 'SMTP value is null'   
            except Exception as e :
                vul_dt['sstatus'] = False
                vul_dt['SMTP'] = '{}의 경로를 찾지 못했습니다'.format(history_xml_path)
                
        except Exception as e:
            vul_dt['sstatus'] = False
            vul_dt['SMTP'] = 'Histroy의 경로를 찾지 못했습니다다'
        if vul_dt['fstatus'] and vul_dt['hstatus'] and vul_dt['sstatus'] :
            error_dt['status'] = 'Good'
            error_dt['value'] = vul_dt
        else :
            error_dt['status'] = 'Weak'
            error_dt['value'] = vul_dt
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-32 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

#[SW2-33]
error_dt = {}
error_list = []
error_dt['SWV'] = 'SW2-33'
try :
    cmd = os.popen('net start | find /I "Telnet"').read()
    logging.info('{} : !!!!!!SWV2-33 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if len(cmd) == 0 :
        error_dt['value'] = "Telnet 서비스 구동안함 및 사용안함"
        error_dt['status'] = 'Good'
    else :
        cmd = os.popen('tlntadmn config').readlines()
        for i in cmd :
            if 'NTLM' in i :
                error_dt['value'] = i.strip()
                error_dt['status'] = 'Good'
                break
            else :
                error_dt['value'] = 'NTLM 방식을 사용하고 있지 않습니다'
                error_dt['status'] = 'Weak'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-33 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-34]
error_dt = {}
error_list = []
nline = []
error_dt['SWV'] = 'SW2-34'
try :
    logging.info('{} : !!!!!!SWV2-34 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | find /I "MaxIdleTime"').readlines()
    if len(cmd) == 0 :
        error_dt['value'] = "Timeout 제어 설정이 되어있지않습니다."
        error_dt['status'] = 'Weak'
    else :
        for line in cmd :
            nline.append(line.split('\n')[0])
        nline = filter(None, nline)
        for i in nline :
            if 'fInherit' in i :
                continue
            error_dt['value'] = "TimeOut 제어 : {}, {}분 설정".format(i.strip(), int(i.strip().split('REG_DWORD')[1].strip(), 16)//1000//60)
            if int(i.strip().split('REG_DWORD')[1].strip(), 16) == 0 :
                error_dt['status'] = 'Weak'
            else :
                error_dt['status'] = 'Good'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-34 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-35]
error_list = []
cmd_list  = []
error_dt = {}
try :
    logging.info('{} : !!!!!!SWV2-35 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('schtasks').read().splitlines()
    for i in cmd :
        if i == '' :
            error_list.append(cmd_list)
            cmd_list = []
            continue
        cmd_list.append(i)
    error_list = [v for v in error_list if v]
    error_dt['SWV'] = 'SW2-35'
    error_dt['value'] = '불필요한 예약된 작업 정의 바람'
    error_dt['status'] = 'Weak'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-35 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-36]
error_dt = {}
dt = {}
error_list = []
error_dt['SWV'] = 'SW2-36'
try :
    logging.info('{} : !!!!!!SWV2-36 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\Rdpwd\Tds\Tcp" | find /I "PortNumber"').read()
    nline = filter(None, cmd.split(' '))
    for i in nline :
        if 'PortNumber' in i:
            dt['name'] = i
        elif 'REG_DWORD' in i :
            continue
        else:
            dt['value'] = int(i, 16)
    if dt['value'] == 3389 :
        error_dt['value'] = dt
        error_dt['status'] = 'Weak'
    else :
        error_dt['value'] = dt
        error_dt['status'] = 'Good'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-36 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-37]
count = 0
error_dt = {}    
error_dt['SWV'] = 'SW2-37'
try :
    logging.info('{} : !!!!!!SWV2-37 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    for i in system_list :
        if 'SMTP' in i['DISPLAY_NAME'] :
            if 'RUNNING' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Weak'
                break
            elif 'STOP' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Good'
                break
            elif 'PAUSED' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Weak'
        else :
            error_dt['value'] = 'SMTP 서비스 존재하지않음'
            error_dt['status'] = 'Good'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-37 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-38]
error_dt = {}
error_dt['SWV'] = 'SW2-38'
try :
    logging.info('{} : !!!!!!SWV2-38 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    os.chdir("\\Windows\\System32\\inetsrv")
    dns_server = os.popen('net start | find /I "DNS Server"').read()
    if len(dns_server) == 0 :
        error_dt['value'] = "DNS 서비스사용하지 않음"
        error_dt['status'] = 'Good'
    else :
        try :
            key = reg.HKEY_LOCAL_MACHINE
            key_value = "System\\CurrentControlSet\\Services\\DNS\\Parameters"
            open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            value, type1 = reg.QueryValueEx(open, "NoRecursion")
            if int(value) == 1 :
                error_dt['value'] = 'NoRecursion : {}'.format(value)
                error_dt['status'] = 'Good'
            else :
                error_dt['value'] = 'NoRecursion : {}'.format(value)
                error_dt['status'] = 'Weak'
        except :
            error_dt['value'] = 'Recursive Query 제한 레지스트리 존재 안함'
            error_dt['status'] = 'Weak'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-38 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

# [SW2-39]
error_dt = {}    
error_dt['SWV'] = 'SW2-39'
try :
    logging.info('{} : !!!!!!SWV2-39 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    for i in system_list :
        if 'Telnet' in i['DISPLAY_NAME'] :
            if 'RUNNING' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Weak'
                break
            elif 'STOP' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Good'
                break
            elif 'PAUSED' in i['STATUS'] :
                error_dt['value'] = i
                error_dt['status'] = 'Weak'
        else :
            error_dt['value'] = 'Telnet 서비스 존재하지않음'
            error_dt['status'] = 'Good'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-39 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

# [SW2-40]
error_list = []
error_dt = {}    
error_dt['SWV'] = 'SW2-40'
try :
    logging.info('{} : !!!!!!SWV2-40 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('net share').read().splitlines()
    bool = "False"
    for i in cmd :
        if bool == "False" :
            if '--------------------------' in i:
                bool = "True"
        else :
            if '명령을 잘 싱행했습니다.' in i :
                continue
            error_list.append(i)
    error_list = [v for v in error_list if v]
    if len(error_list) == 0 or len(list(filter(lambda x : 'ADMIN$ ' not in x, error_list))) == 0: 
        error_dt['value'] = error_list
        error_dt['status'] = 'Good'
    else :
        error_dt['value'] = error_list
        error_dt['status'] = 'Weak'
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-40 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

#[SW2-41]
error_dt = {}
error_dt['SWV'] = 'SW2-41'
try :
    logging.info('{} : !!!!!!SWV2-41 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    os.chdir("\\Windows\\System32\\inetsrv")
    cmd = os.popen('net start | find /I "DNS Server"').read()
    if len(cmd) == 0 :
        error_dt['value'] = "DNS 서비스 사용하지 않음"
        error_dt['status'] = 'Good'
    else :
        cmd = os.popen('reg query "HKLM\software\microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "AllowUpdate"').read().splitlines()
        if len(cmd) == 0 :
            error_dt['status'] = "Weak"
            error_dt['value'] = "allowupdate 레지스트리가 존재하지 않습니다."
        else :
            for i in cmd :
                if '0x1' in i :
                    error_dt['status'] = "Weak"
                    error_dt['value'] = "DNS : {}".format(cmd)
                    break
                elif '0x0' in i :
                    error_dt['status'] = "Good"
                    error_dt['value'] = "DNS : {}".format(cmd)
        if 'status' not in error_dt :
            error_dt['status'] = "Weak"
            error_dt['value'] = "allowupdate 레지스트리가 존재하지 않습니다."
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-41 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-42]
error_dt = {}
dt = {}
stratum = 0
error_dt['SWV'] = 'SW2-42'
try :
    logging.info('{} : !!!!!!SWV2-42 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('w32tm /query /status').read().splitlines()
    for i in range(len(cmd)) :
        if '계층' in cmd[i] or 'Stratum' in cmd[i]:
            stratum = i
            break
    if stratum == 0 :
        error_dt['status'] = 'Weak'
        error_dt['value'] = 'NTP 서비스가 작동중이지 않습니다'
    else :
        if 'ntp' in cmd[stratum].lower() :
            error_dt['status'] = 'Good'
            error_dt['value'] = cmd[stratum]
        else :
            error_dt['status'] = 'Weak'
            error_dt['value'] = cmd[stratum]
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-42 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
tanium.results.add(tanium_list)