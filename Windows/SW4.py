"exec" "env" "TANIUM_SENSOR=1" "`pwd`/`if [ -f TPython/TPython ]; then echo TPython/TPython; else echo python27/python; fi`" "$0" "$@" 
from datetime import datetime
import logging
import os
import re
result = []
lst = []
result_list = []
sessionBool = False
warnBool = False
secBool = 2
privilegeBool = False
os.system('secedit /export /cfg .\\test.inf')
text = open('.\\test.inf', 'rb')
y = text.read()
x = y.decode('utf-16')
text.close()
result = x.splitlines()
status = ""
for x in result :
    dict = {}
    if 'ShutdownWithoutLogon' in x :
        dict['SWV'] = 'SW4-04'
        try :
            logging.info('{} : !!!!!!SWV4-04 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split(',')[1]
            if int(value) == 0 :
                status = "Good"
            else :
                status = "Weak"
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-04 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'SeRemoteShutdownPrivilege' in x : 
        dict['SWV'] = 'SW4-05'
        try :
            logging.info('{} : !!!!!!SWV4-05 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split('*')[1]
            if value == 'S-1-5-32-544' :
                status = "Good"
            else :
                status = "Weak"
            dict['status'] = status          
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-05 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'CrashOnAuditFail' in x : 
        dict['SWV'] = 'SW4-06'
        try :
            logging.info('{} : !!!!!!SWV4-06 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split(',')[1]
            if int(value) == 0 :
                status = "Good"
            else :
                status = "Weak"
            dict['status'] = status 
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-06 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'RestrictAnonymous=' in x : 
        dict['SWV'] = 'SW4-07'
        try :
            logging.info('{} : !!!!!!SWV4-07 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split(',')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-07 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'AddPrinterDrivers' in x : 
        dict['SWV'] = 'SW4-12'
        try :
            logging.info('{} : !!!!!!SWV4-12 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split(',')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-12 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'EnableForcedLogOff' in x : 
        dict['SWV'] = 'SW4-13'
        try :
            logging.info('{} : !!!!!!SWV4-13 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if sessionBool == True :
                continue
            value = x.strip().split(',')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            if status == "Weak" :
                sessionBool = True
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-13 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    elif 'AutoDisconnect' in x : 
        dict['SWV'] = 'SW4-13'
        try :
            logging.info('{} : !!!!!!SWV4-13 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if sessionBool == True :
                continue
            value = x.strip().split(',')[1]
            if int(value) == 15 :
                status = "Good"
            else :
                status = "Weak"
            if status == "Weak" :
                sessionBool = True
            else :
                continue
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-13 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'LegalNoticeCaption' in x :
        dict['SWV'] = 'SW4-14'
        try :
            logging.info('{} : !!!!!!SWV4-14_1 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))        
            if warnBool == True :
                continue
            value = x.strip().split('=1,')[1]
            if value == '""' :
                status = "Weak"
            else :
                status = "Good"
            if status == "Weak" :
                warnBool = True
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-14 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    elif 'LegalNoticeText' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-14_2 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if warnBool == True :
                continue
            value = x.strip().split('=')[1]
            if value == '7,' :
                status = "Weak"
            else :
                status = "Good"
            if status == "Weak" :
                warnBool = True
            else :
                continue
            dict['SWV'] = 'SW4-14'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-13 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'LmCompatibilityLevel' in x : #* 
        try :
            logging.info('{} : !!!!!!SWV4-16 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split('=4,')[1]
            if int(value) == 3 :
                status = "Good"
            else :
                status = "Weak"
            dict['SWV'] = 'SW4-16'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-16 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'AllocateDASD' in x : #*
        try :
            logging.info('{} : !!!!!!SWV4-09 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split(',')[1] 
            if value == '"0"' :
                status = "Good"
            else :
                status = "Weak"
            dict['SWV'] = 'SW4-09'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-09 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'RequireSignOrSeal' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-17 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if secBool == 0 :
                continue
            value = x.strip().split('=4,')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            if status == "Weak" :
                secBool = 1
            else :
                continue
            dict['SWV'] = 'SW4-17'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-17 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    elif 'SealSecureChannel' in x :
        try :
            logging.info('{} : !!!!!!SWV4-17_1 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S'))) 
            if secBool == 1 :
                continue
            value = x.strip().split('=4,')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            if status == "Weak" :
                secBool = 0
            else :
                continue
            dict['SWV'] = 'SW4-17'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-17 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    elif 'SignSecureChannel' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-17_2 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if secBool == 1 :
                continue
            value = x.strip().split('=4,')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            if status == "Weak" :
                secBool = 0
            dict['SWV'] = 'SW4-17'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-17 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'ClearPageFileAtShutdown' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-20 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split('=4,')[1]
            if int(value) == 1 :
                status = "Good"
            else :
                status = "Weak"
            dict['SWV'] = 'SW4-20'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-20 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'SeBackupPrivilege' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-24 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if privilegeBool == True :
                continue
            value = x.strip().split('= ')[1]
            keywords = ["*S-1-1-0", "*S-1-5-32-546", "*S-1-5-32-544"]
            valueRS = any(k in value for k in keywords)
            if valueRS == False :
                status = "Good"
            else :
                status = "Weak"
                privilegeBool = True
            dict['SWV'] = 'SW4-24'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-24 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    elif 'SeRestorePrivilege' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-24 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            if privilegeBool == True :
                continue
            value = x.strip().split('= ')[1]
            keywords = ["*S-1-1-0", "*S-1-5-32-546", "*S-1-5-32-544"]
            valueRS = any(k in value for k in keywords)
            if valueRS == False :
                status = "Good"
            else :
                status = "Weak"
            if status == "Weak" :
                privilegeBool = True
            else :
                continue               
            dict['SWV'] = 'SW4-24'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-24 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'SeTakeOwnershipPrivilege' in x : 
        try :
            logging.info('{} : !!!!!!SWV4-22 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            value = x.strip().split('= ')[1]
            if value == "*S-1-5-32-544" :
                status = "Good"
            else :
                status = "Weak"
            dict['SWV'] = 'SW4-22'
            dict['status'] = status
            dict['value'] = x
        except Exception as e:
            logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
            dict['status'] = 'error'
            dict['value'] = str(e)
        logging.info('{} : !!!!!!SWV4-22 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    if 'status' in dict :
        result_list.append(dict)
count = 0
ninebool = False
sixteenbool = False
for i in result_list :
    if i['SWV'] == 'SW4-09':
        break
    elif i['SWV'] == 'SW4-16':
        break
    else :
        count = count+ 1
    if count == len(result_list) :
        ninebool = True
        sixteenbool = True
if ninebool:
    dict = {}
    logging.info('{} : !!!!!!SWV4-09 value is not enabled!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['SWV'] = 'SW4-09'
    dict['status'] = 'Weak'
    dict['value'] = "'이동식 미디어 포맷 및 꺼내기 허용'정책이 정의되어 있지않습니다."
    result_list.append(dict)
    logging.info('{} : !!!!!!SWV4-16 value has been filled'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
if sixteenbool:
    dict = {}
    logging.info('{} : !!!!!!SWV4-16 value is not enabled!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['SWV'] = 'SW4-16'
    dict['status'] = 'Weak'
    dict['value'] = "'Lan Manager 인증'정책이 정의되어 있지않습니다."
    logging.info('{} : !!!!!!SWV4-16 value has been filled'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    result_list.append(dict)
# 4-01
dict = {}
dict['SWV'] = 'SW4-01'
try :
    logging.info('{} : !!!!!!SWV4-01 Start!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    cmd = os.popen(r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" ').readlines()
    path = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    cmdSplit = []
    for l in cmd :
        cmdSplit.append(l.split('\n')[0])
    cmdSplit = [v for v in cmdSplit if v]
    cmdSplit = [w.strip(path) for w in cmdSplit ]  
    keywords = ['{19DD1D8D-927F-45DF-ADF4-75D38267848D}']
    cmdRS = any(k in keywords for k in cmdSplit)
    if cmdRS == True :
        status = "Good"
        value = "바이러스 백신 프로그램이 설치되어 있습니다."
    else :
        status = "Weak"
        value = "바이러스 백신 프로그램이 설치되어 있지 않습니다."
    dict['status'] = status
    dict['value'] = value
except Exception as e:
    logging.info('{} : ******Error is ocurred********'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
    dict['status'] = 'error'
    dict['value'] = str(e)
logging.info('{} : !!!!!!SWV4-01 End!!!!'.format((datetime.today()).strftime('%Y-%m-%d %H:%M:%S')))
lst.append(result_list)
result_list.append(dict)
tanium.results.add(result_list)
