"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
#-*- coding: utf-8 -*-
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
# import tanium
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
#[SW2-12]
count = 0
dt = {}
error_list = []
error_dt = {}
asa = False
asax = False
# asa/asax = True : 양호
# asa/asax = false : 취약
error_dt['SWV'] = 'SW2-12'
try :
    logging.info('{} : !!!!!!SWV2-12 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else:
        for i in result :
            for j in i['text'] :
                if 'system.webServer/security/requestFiltering' in j :
                    for y in i['text'] :
                        if '".asa"' in y :
                            split = y.split(' ')
                            for z in split:
                                if 'allowed' in z :
                                    if z.split('=')[1].replace('"', '') == 'false' :
                                        asa = True
                                    elif z.split('=')[1].replace('"', '') == 'true' :
                                        asa = False
                        elif '".asax"' in y :
                            split = y.split(' ')
                            for z in split:
                                if 'allowed' in z :
                                    if z.split('=')[1].replace('"', '') == 'false' :
                                        asax = True
                                    elif z.split('=')[1].replace('"', '') == 'true' :
                                        asax = False
                if 'system.applicationHost/sites' in j :
                        for y in i['text'] :
                            if 'physicalPath' in y :
                                split = y.split(' ')
                                for z in split:
                                    if 'physicalPath' in z :
                                        path = z.split('=')[1].strip('"')
                                        break
        for i in range(2) :
            dt = {}
            dt['path'] = '\\Windows\\System32\\inetsrv'
            if i == 0 :
                if asa : 
                    dt['name'] = 'asa' 
                    dt['value'] = True
                else :
                    dt['name'] = 'asa'
                    dt['value'] = False   
            elif i == 1 :
                if asax : 
                    dt['name'] = 'asax' 
                    dt['value'] = True
                else :
                    dt['name'] = 'asax'
                    dt['value'] = False
            error_list.append(dt)
        #C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config web.config
        key = reg.HKEY_LOCAL_MACHINE
        key_value = "SOFTWARE\Microsoft\\NET Framework Setup\\Ndp\V4\Full"
        open = reg.OpenKey(key, key_value, 0, reg.KEY_READ)
        value, type1 = reg.QueryValueEx(open, "InstallPath")
        open.Close()
        web_config_path = str(value).replace('\\', '\\\\') + 'Config\\web.config'
        web_config = ET.parse(web_config_path)
        root = web_config.getroot()
        add = root.iter('add')
        for i in add :
            i = ET.tostring(i, encoding='unicode')
            if '*.asax' in i :
                if 'HttpForbiddenHandler' in i :
                    asax = True
            elif '*.asa' in i :
                if 'HttpForbiddenHandler' in i :
                    asa = True
        for i in range(2) :
            dt = {}
            dt['path'] = web_config_path
            if i == 0 :
                if asa : 
                    dt['name'] = 'asa' 
                    dt['value'] = True
                else :
                    dt['name'] = 'asa'
                    dt['value'] = False   
            elif i == 1 :
                if asax : 
                    dt['name'] = 'asax' 
                    dt['value'] = True
                else :
                    dt['name'] = 'asax'
                    dt['value'] = False
            error_list.append(dt)
        # %SystemDrive%\inetpub\wwwroot web.config
        web_config_path = path.replace('%SystemDrive%', 'C:') + '\web.config'
        if os.path.exists(web_config_path) :
            web_config = ET.parse(web_config_path)
            root = web_config.getroot()
            add = root.iter('add')
            for i in add :
                if i.attrib['fileExtension'] == '.asax' :
                    if i.attrib['allowed'] == 'false' :
                        asax = True
                    elif i.attrib['allowed'] == 'true' :
                        asax = False
                elif i.attrib['fileExtension'] == '.asa':
                    if i.attrib['allowed'] == 'false' :
                        asa = True
                    elif i.attrib['allowed'] == 'true' :
                        asa = False
        for i in range(2) :
            dt = {}
            dt['path'] = web_config_path
            if i == 0 :
                if asa : 
                    dt['name'] = 'asa' 
                    dt['value'] = True
                else :
                    dt['name'] = 'asa'
                    dt['value'] = False   
            elif i == 1 :
                if asax : 
                    dt['name'] = 'asax' 
                    dt['value'] = True
                else :
                    dt['name'] = 'asax'
                    dt['value'] = False
            error_list.append(dt)
    for i in error_list :
        if not i['value'] :
            error_dt['status'] = 'Weak'
        else :
            error_dt['status'] = 'Good'
    error_dt['value'] = error_list
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-12 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-13]
error_dt = {}
error_dt['SWV'] = 'SW2-13'
try :
    logging.info('{} : !!!!!!SWV2-13 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    try :
        key = reg.HKEY_LOCAL_MACHINE
        key_value = "SOFTWARE\Microsoft\InetStp"
        open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
        value, type1 = reg.QueryValueEx(open, "SetupString")
        open.Close()
        if float(value.split(' ')[1].strip()) < 6.0 :
            error_dt['value'] = 'IIS 6.0 이하 버전임(' + value + ')'
            error_dt['status'] = 'Weak'
        else :
            error_dt['value'] = 'IIS 6.0 이상 버전은 해당없음(' + value + ')'
            error_dt['status'] = 'Good'
    except :
        error_dt['value'] = "IIS 설치되어있지않음"
        error_dt['status'] = 'Good'
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-13 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-14]
count = 0
root = ""
error_dt = {}
error_list = []
error_dt['SWV'] = 'SW2-14'
try :
    logging.info('{} : !!!!!!SWV2-14 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else:
        for i in result :
            for j in i['text'] :
                if 'system.applicationHost/sites' in j :
                    for y in i['text'] :
                        dt = {}
                        if 'physicalPath' in y :
                            split = y.split(' ')
                            for z in split:
                                if 'physicalPath=' in z :
                                    root = z.split('=')[1].strip('"')
                                    break
                            break
                        else :
                            dt['name'] = 'physicalPath'
                            dt['value'] = '값이 없음'
                        count = count + 1
                        if count == len(i['text']) and len(error_list) == 0:
                            error_list.append(dt)
                            break
        if len(error_list) == 0 :
            cmd = os.popen('icacls "' + root + '" | findstr /i "everyone" 2>null ').readlines()
            if len(cmd) == 0 :
                error_dt['status'] = 'Good'
                error_dt['value'] = 'everyone 값이 없음'
            else :
                error_dt['status'] = 'Weak'
                error_dt['value'] = cmd
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-14 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
# [SW2-15]
count = 0
for_count = 0
error_dt = {}
error_dt['SWV'] = 'SW2-15'
status_home = ''
value_home = ''
error_list = []
try :
    logging.info('{} : !!!!!!SWV2-15 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good' 
    else:
        for i in result :
            for j in i['text'] :
                if 'system.webServer/handlers' in j :
                    for y in i['text'] :
                        dt = {}
                        if '"*.htr"' in y :
                            split = y.split(' ')
                            for z in split:
                                if '*.htr' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        elif '"*.idc"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.idc' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        elif '"*.stm"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.stm' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt) 
                            count = count + 1  
                        elif '"*.shtm"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.shtm' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        elif '"*.shtml"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.shtml' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        elif '"*.#printer"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.#printer' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        elif '"*.htw"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.htw' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt) 
                            count = count + 1
                        elif '"*.ida"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.ida' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        elif '"*.idq"' in y:
                            split = y.split(' ')
                            for z in split:
                                if '*.idq' in z :
                                    dt['value'] = z
                                if 'name' in z :
                                    dt['name'] = z.strip("'name=").strip('"')
                            error_list.append(dt)
                            count = count + 1
                        for_count = for_count + 1
                        if for_count == len(i['text']) and len(error_list) == 0:
                            status_home = "Good"
                            value_home = 'Home : 매핑(.htr .idc .stm .shtm .shtml .printer .htw .ida .idq) 존재하지않음'
                            break
    if len(error_list) > 0 :
        status_home = "Weak"
        value_home = 'Home : {}'.format(error_list)
    cmd = os.popen('echo %WINDIR%').read()
    root = cmd.strip() + '\\System32\\Inetsrv\\Config\\applicationHost.config'
    error_list = []
    status = ''
    value = ''
    if os.path.exists(root) :
        web_config = ET.parse(root)
        root = web_config.getroot()
        add = root.iter('add')
        for i in add :
            dt = {}
            if 'path' in i.attrib :
                if '*.htr' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.idc' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.stm' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.shtm' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.shtml' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.printer' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.htw' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.ida' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.idq' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
                elif '*.cer' in i.attrib['path'] :
                    dt['value'] = i.attrib['path']
                    dt['name'] = i.attrib['name']
            if 'value' in dt :
                error_list.append(dt)
                
        remove_list = []
        add_list = []
        location = root.iter('location')
        for i in location :
            handlers = i.iter('handlers')
            for i in handlers :
                for j in i.iter(tag='remove') :
                    remove_list.append(j.attrib['name'])
                for j in i.iter(tag='add') :
                    add_list.append(j.attrib['name'])
        if len(error_list) == 0 : 
            status = 'Good'
            value = '매핑(.htr .idc .stm .shtm .shtml .printer .htw .ida .idq) 존재하지않음'
        else : 
            if len(remove_list) == 0 and len(add_list) == 0:
                status ='Weak'
            elif len(remove_list) == 0 :
                status = 'Weak'
            elif len(remove_list) != 0 :
                for i in remove_list :
                    for j in error_list :
                        if i == j['name'] :
                            status = 'Good'
                            value = j['name']
                            break
                if status == '' :
                    status = 'Weak'
                if status == 'Good' and len(add_list) != 0 :
                    for i in add_list :
                        if i == value :
                            status = 'Weak'
                else :
                    value = '매핑(.htr .idc .stm .shtm .shtml .printer .htw .ida .idq) 존재하나 제거되어있음'
    value = 'Default_web_site : {}'.format(value)
    if status == 'Weak' or status_home == 'Weak' :
        error_dt['status'] = 'Weak'
        error_dt['value'] = [value, value_home]
    else :
        error_dt['status'] = 'Good'
        error_dt['value'] = [value, value_home]
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-15 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

#[SW2-16]
error_dt = {}
error_dt['SWV'] = 'SW2-16'
try:
    logging.info('{} : !!!!!!SWV2-16 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    key = reg.HKEY_LOCAL_MACHINE
    key_value = "SOFTWARE\Microsoft\InetStp"
    open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
    value, type1 = reg.QueryValueEx(open, "SetupString")
    if float(value.split(' ')[1].strip()) < 6.0 :
        try :
            key_value = "SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"
            open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            value, type1 = reg.QueryValueEx(open, "SSIEnableCmdDirective")
            if value == 1 :
                error_dt['value'] = 'SSIEnableCmdDirective : {}'.format(value)
                error_dt['status'] = 'Weak'
            elif value == 0 :
                error_dt['value'] = 'SSIEnableCmdDirective : {}'.format(value)
                error_dt['status'] = 'Good'
        except :
            error_dt['value'] = 'SSIEnableCmdDirective is Null'
            error_dt['status'] = 'Weak'
    else :
        error_dt['value'] = 'IIS 6.0 이상 버전은 해당없음(' + value + ')'
        error_dt['status'] = 'Good'
except:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['value'] = 'IIS 설치되어있지않음'
    error_dt['status'] = 'Good'
logging.info('{} : !!!!!!SWV2-16 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-17]
for_count = 0
error_dt = {}
error_list = []
error_dt['SWV'] = 'SW2-17'
try :
    logging.info('{} : !!!!!!SWV2-17 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if IIS_bool == "True" :
        error_dt['value'] = 'IIS가 설치되어있지않음'
        error_dt['status'] = 'Good'
    else:
        for i in result :
            for j in i['text'] :
                if 'system.webServer/security/isapiCgiRestriction' in j :
                    for y in i['text'] :
                        dt = {}
                        if '"WebDAV"' in y :
                            split = y.split(' ')
                            for z in split:
                                if 'allowed="true"' in z :
                                    dt['value'] = 'WebDAV' + z
                                    dt['status'] = 'Weak'
                                    error_list.append(dt)
                                    break
                                elif 'allowed="false"' in z :
                                    dt['value'] = 'WebDAV' + z
                                    dt['status'] = 'Good'
                                    error_list.append(dt)
                                    break
                        else :
                            dt['value'] = 'WEBDAV is null'
                            dt['status'] = 'Good'
        if len(error_list) > 0 :
            error_dt['value'] = error_list[0]['value']
            error_dt['status'] = error_list[0]['status']
        else :
            error_dt['value'] = dt['value']
            error_dt['status'] = dt['status']
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-17 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)
#[SW2-18]
nline = []
error_dt = {}
dt = {}
error_list = []
reg_list = []
netbios = []
error_dt['SWV'] = 'SW2-18'
# cmd = os.popen('reg query "HKLM\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces" /s').read()
# pprint(cmd)
try :
    logging.info('{} : !!!!!!SWV2-18 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    try :
        key = reg.HKEY_LOCAL_MACHINE
        key_value = "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces"
        open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
        for i in range(5000) :
            reg_dict = {}
            keyname = reg.EnumKey(open, i)
            varSubkey2 = "%s\\%s" % (key_value, keyname) 
            varKey2 = reg.OpenKey(key, varSubkey2, 0 , reg.KEY_ALL_ACCESS)
            value, type1 = reg.QueryValueEx(varKey2, "NetbiosOptions")
            reg_dict['name'] = str(keyname)[str(keyname).find('{'):]
            reg_dict['value'] = value
            reg_list.append(reg_dict)
    except :
        if len(reg_list) == 0 :
            cmd = os.popen("""wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" get Description, TcpipNetbiosOptions""").readlines()
            for line in cmd :
                nline.append(line.split('\n')[0])
            nline = filter(None, nline)
            for i in nline :
                if 'TcpipNetbiosOptions' in i :
                    index = i.find('T')
                else :
                    dt['name'] = i[:index]
                    dt['value'] = i[index]
                    error_list.append(dt)
            error_list = [v for v in error_list if v]
            for i in error_list :
                if int(i['value']) == 2 :
                    error_dt['value'] = error_list
                    error_dt['status'] = 'Good'
                else :
                    error_dt['value'] = error_list
                    error_dt['status'] = 'Weak'
            tanium_list.append(error_dt)
    try :
        key = reg.HKEY_LOCAL_MACHINE
        key_value = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
        open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
        for i in range(5000) :
            reg_dict = {}
            keyname = reg.EnumKey(open, i)
            varSubkey2 = "%s\\%s" % (key_value, keyname) 
            varKey2 = reg.OpenKey(key, varSubkey2, 0 , reg.KEY_ALL_ACCESS)
            value, type1 = reg.QueryValueEx(varKey2, "ServiceName")
            reg_dict['name'] = value
            netbios.append(reg_dict)
    except :
        if len(netbios) == 0 :
            for i in reg_list :
                if int(i['value']) != 2 :
                    error_list.append(i)
            if len(error_list) > 0 :
                error_dt['value'] = 'NetBios는 구동중이지 않으나 설정에서 취약한 항목 {} 들이 있습니다.'.format(error_list)
                error_dt['status'] = 'Weak'
            else :
                error_dt['value'] = error_list
                error_dt['status'] = 'Good'
        else :
            for regst in reg_list :
                for net in netbios :
                    if regst['name'].upper() == net['name'].upper() :
                        if int(regst['value']) != 2 :
                            error_list.append(regst)
            if len(error_list) > 0 :
                error_dt['value'] = '구동중인 NetBios에서 취약한 항목 {} 들이 있습니다.'.format(error_list)
                error_dt['status'] = 'Weak'
            else :
                error_dt['value'] = '구동중인 NetBios에서 취약한 항목이 없습니다.'
                error_dt['status'] = 'Good'
except Exception as e:
    logging.error('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    error_dt['status'] = 'error'
    error_dt['value'] = str(e)
logging.info('{} : !!!!!!SWV2-18 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
tanium_list.append(error_dt)

from pprint import pprint
pprint(tanium_list)
# tanium.results.add(tanium_list)