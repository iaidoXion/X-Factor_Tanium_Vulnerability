"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
from datetime import datetime
import logging
import os
import re
result_list = []
lst = []
# 4-02
dict = {}
dict['SWV'] = 'SW4-02'
try :
    logging.info('{} : !!!!!!SWV4-02 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen(r'cacls %systemroot%\system32\config\SAM | find ":F"').readlines()
    cmdSplit = []
    for l in cmd :
        cmdSplit.append(l.split('\n')[0])
    cmdSplit = [w.strip('C:\\Windows\\system32\\config\\SAM') for w in cmdSplit ] 
    value = []
    for k in range(len(cmdSplit)) :
        value.append(re.search('\\\\(.+?):F', cmdSplit[k]).group(1))
    cmdGW = []
    for x in range(len(value)) :
        cmdGW.append(re.sub("SYSTEM|Administrators", "", value[x]))
    cmdRS = [v for v in cmdGW if v]
    if not cmdRS :
        status = "Good"
    if cmdRS :
        status = "Weak"  
    dict['status'] = status
    dict['value'] = value
    lst.append(result_list)
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-02 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
result_list.append(dict)
    
# 4-03
dict = {}
dict['SWV'] = 'SW4-03'
try :
    logging.info('{} : !!!!!!SWV4-03 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('reg query "HKEY_USERS\"').readlines()
    cmdExtract = [s for s in cmd if "S-1" in s]
    cmdPath = []
    for x in range (len(cmdExtract)) :
        a = os.popen('reg query "%s\"' % cmdExtract[x]).readlines()
        b = [s for s in a if "Control Panel" in s]
        cmdPath.append(b) 
    cmdPath = sum(cmdPath, [])
    cmdStrip = [l.strip() for l in cmdPath]
    cmdDeepPath = []
    for x in range (len(cmdStrip)) :        
        cmdDeepPath.append(os.popen('reg query "%s\Desktop\"' % cmdStrip[x]).readlines())
    cmdSum = sum(cmdDeepPath, [])
    screenValue = [s for s in cmdSum if "ScreenSave" in s]
    svStrip = [l.strip() for l in screenValue]
    valueTF = list(set(svStrip))
    cmdRS = []
    screenRS = []
    if len(valueTF) >= 3:
        for k in range(len(valueTF)) :
            if 'ScreenSaverIsSecure' in valueTF[k] :
                screenRS = re.sub(r'[^0-9]', '', valueTF[k])
                if screenRS != '1' :
                    cmdRS.append(k)
            if 'ScreenSaveActive' in valueTF[k] :
                screenRS = re.sub(r'[^0-9]', '', valueTF[k])
                if screenRS != '1' :
                    cmdRS.append(k)
            if 'ScreenSaveTimeOut' in valueTF[k] :
                screenRS = re.sub(r'[^0-9]', '', valueTF[k])
                if int(screenRS) < 600 : # 단위 초
                    cmdRS.append(k)
        if cmdRS :
            scStatus = "Weak"
        else :
            scStatus = "Good"
    else :
        scStatus = "Weak"
    dict['status'] = scStatus 
    dict['value'] = valueTF
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-03 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)

# 4-08
dict = {}
dict['SWV'] = 'SW4-08'
try :
    logging.info('{} : !!!!!!SWV4-08 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | find /I "AutoAdminLogon"').readlines()
    cmdSplit = []
    for l in cmd :
        cmdSplit.append(l.split('\n')[0])
    cmdString = ' '.join(s for s in cmdSplit)
    if not cmd :
        status = "Good"
        value = "AutoAdminLogon 값이 없습니다."
    else : 
        cmdNum = re.sub(r'[^0-9]', '', cmdString)
        if int(cmdNum) == 0:
            status = "Good"
        else : 
            status = "Weak"
        value = int(cmdNum)
    dict['status'] = status 
    dict['value'] = value 
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-08 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)

# 4-10
dict={}
dict['SWV'] = 'SW4-10'
try :
    logging.info('{} : !!!!!!SWV4-10 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd= os.popen('manage-bde -status').readlines()
    cmdSplit = [l.strip() for l in cmd]
    cmdExtract = [x for x in cmdSplit if 'BitLocker 버전:' in x]
    cmdString = ' '.join(s for s in cmdExtract)
    value = cmdString.replace(" ", "")
    if "없음" in cmdString :
        status = "Weak"
    else :
        status = "Good"
    dict['status'] = status 
    dict['value'] = value
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-10 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)

# 4-11
dict={}
dict['SWV'] = 'SW4-11'
try :
    logging.info('{} : !!!!!!SWV4-11 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen('reg query "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"').readlines()
    cmdSplit=[]
    for line in cmd :
        cmdSplit.append(line.split('\n')[0])
    cmdSplit = [v for v in cmdSplit if v]
    cmdnotIn = [x for x in cmdSplit if '\\CurrentControlSet' not in x]
    def all_exist(avalue, bvalue):
        return all(any(x in y for y in bvalue) for x in avalue)
    # def any_exist(avalue, bvalue):
    #     return any(any(x in y for y in bvalue) for x in avalue)
    keywords=["NoNameReleaseOnDemand", "EnableDeadGWDetect", "SynAttackProtect", "KeepAliveTime"]
    cmdTF = all_exist(keywords, cmdnotIn)
    cmdList =[]
    if cmdTF == False :
        status = "Weak"
    else :
        for x in cmdnotIn:          
            if "NoNameReleaseOnDemand" in x:
                cmdRS = x.strip("    NoNameReleaseOnDemand    REG_DWORD    0x")
                if int(cmdRS) == 1 :
                    cmdGW = "Good"
                else :
                    cmdGW = "Weak"
                cmdList.append(cmdGW)
            if "EnableDeadGWDetect" in x:
                cmdRS = x.strip("    EnableDeadGWDetect    REG_DWORD    ")
                if cmdRS == "0x0" :
                    cmdGW = "Good"
                else :
                    cmdGW = "Weak"
                cmdList.append(cmdGW)
            if "SynAttackProtect" in x:
                cmdRS = x.strip("    SynAttackProtect    REG_DWORD    0x")
                if int(cmdRS) >= 1 :
                    cmdGW = "Good"
                else :
                    cmdGW = "Weak"
                cmdList.append(cmdGW)
            if "KeepAliveTime" in x:
                cmdRS = x.strip("    KeepAliveTime    REG_DWORD    0x")
                if cmdRS == "493" :
                    cmdGW = "Good"
                else :
                    cmdGW = "Weak"  
                cmdList.append(cmdGW)
        if 'Weak' in cmdList :
            status = "Weak"
        else :
            status = "Good"
    value = []
    for x in cmdnotIn: 
        if "NoNameReleaseOnDemand" in x: value.append(x)
        if "EnableDeadGWDetect" in x: value.append(x)
        if "SynAttackProtect" in x: value.append(x)
        if "KeepAliveTime" in x: value.append(x)
    if not value :
        value = "값 전부 없음"
    dict['status'] = status 
    dict['value'] = value 
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-10 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)

# 4-15
dict={}
dict['SWV'] = 'SW4-15'
try :
    logging.info('{} : !!!!!!SWV4-15 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd=os.popen(r'cacls C:\Users\* | find /v "파일을 처리했으며"').read()
    cmdSplit = cmd.split('C:\\')
    cmdSplit = [v for v in cmdSplit if v]
    cmdNotAll = [x for x in cmdSplit if 'Users\\All Users' not in x]
    cmdNotDef = [x for x in cmdNotAll if 'Users\\Default User' not in x]
    cmdRS = all(any(x in y for y in cmdNotDef) for x in ["Everyone"])
    if cmdRS : 
        status = "Weak"
        value = "계정별 홈 디렉터리에 Everyone 권한 있음"
    else : 
        status = "Good"
        value = "계정별 홈 디렉터리에 Everyone 권한 없음"
    dict['status'] = status 
    dict['value'] = value 
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-15 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)

# 4-18
dict={}
dict['SWV'] = 'SW4-18'
try :
    logging.info('{} : !!!!!!SWV4-18 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('fsutil fsinfo volumeinfo c:| find /I "파일 시스템"').read()
    if 'NTFS' in cmd :
        status = "Good"
    else :
        status = "Weak"
    cmdRL = os.popen('fsutil fsinfo volumeinfo c:| find /I "파일 시스템"').readlines()
    value = cmdRL[0].split('\n')[0]
    dict['status'] = status 
    dict['value'] = value 
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-18 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)
# 4-19
dict = {}
dict['SWV'] = 'SW4-19'
try :
    logging.info('{} : !!!!!!SWV4-04 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd= os.popen('reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"').readlines()
    cmdAdd= cmd + os.popen('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"').readlines()
    cmdList= cmdAdd + os.popen('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"').readlines()
    cmdSplit = []
    for l in cmdList :
        cmdSplit.append(l.split('\n')[0])
    cmdSplit = [v for v in cmdSplit if v]
    cmdNotIn = [x for x in cmdSplit if 'CurrentVersion' not in x]
    value = []
    for l in range(len(cmdNotIn)):
        cmdSplReg = cmdNotIn[l].split('    REG_')[0]
        value.append(cmdSplReg.split('    ')[1])
    def any_exist(avalue, bvalue):
        return any(any(x in y for y in bvalue) for x in avalue)  
    keywords=["Downloaded Maps Manager", "Geolocation Service", "IP Helper", "Phone Service", "Sensor Service", "SysMain", "Superfetch", "Windows Biometric Service", "Windows Search"]
    cmdRS = any_exist(keywords, value)
    if cmdRS :
        status = "Weak"
    else :
        status = "Good"
    dict['status'] = status
    dict['value'] = value
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-19 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)
# 4-21
dict={}
dict['SWV'] = 'SW4-21'
try :
    logging.info('{} : !!!!!!SWV4-21 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen('schtasks').readlines()
    cmdExtract=[]
    for i in range(len(cmd)) :
        if "=" not in cmd[i] and "다음 실행 시간" not in cmd[i] and "폴더" not in cmd[i] and "준비" not in cmd[i] and "정보" not in cmd[i]:
            cmdExtract.append(cmd[i])
    cmdReplace = []
    for k in cmdExtract :
        tmp = k.replace("\n","")
        cmdReplace.append(tmp)
    cmdReplace = [v for v in cmdReplace if v]
    cmdSplit = []
    for l in cmdReplace :
        cmdSplit.append(l.split('N/A')[0])
    keywords=["Microsoft Compatibility Appraiser", "ProgramDataUpdater", "StartupAppTask", "Proxy", "Consolidator", "UsbCeip", "RecommendedTroubleshootingScanner", "Scheduled", "Microsoft-Windows-DiskDiagnosticDataCollector", "Microsoft-Windows-DiskDiagnosticResolver", "WinSAT", "AnalyzeSystem", "XblGameSaveTask"]
    value=[]
    for v in cmdSplit :
        value.append(v.replace('  ', ''))
    cmdRS = any_exist(keywords, cmdSplit)
    if cmdRS :
        status = "Weak"
    else :
        status = "Good"
    dict['status'] = status 
    dict['value'] = value 
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-21 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)     
# 4-23
dict = {}
dict['SWV'] = 'SW4-23'
try :
    logging.info('{} : !!!!!!SWV4-23 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd= os.popen('netsh advfirewall firewall show rule name="TaniumClient.exe"').readlines()
    cmdSplit = []
    for line in cmd :
        cmdSplit.append(line.split('\n')[0])
    cmdSplit = [v for v in cmdSplit if v]
    cmdExtract = [x for x in cmdSplit if 'LocalPort' in x]
    cmdJoin = ''.join(cmdExtract)
    if len(cmdJoin) == 0 :
        cmdRS = 'null'
        value = 'null'
    else :
        cmdRS = cmdJoin.split('LocalPort:                            ')[1]
        value = cmdJoin.replace('  ', '')
    if cmdRS == '17472' :
        status = "Good"
    else :
        status = "Weak"
    dict['status'] = status 
    dict['value'] = value 
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-23 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)  
tanium.results.add(result_list)