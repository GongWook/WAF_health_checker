import requests
import urllib3
import time
import datetime
from tqdm import tqdm
import threading
import os

# waf_checker windows size
os.system('mode con: cols=140 lines=50')

# waf_checker ascii art
print("""
                                                                 ,---,                                 ,-.
                               .--.,                           ,--.' |                             ,--/ /|
         .---.               ,--.'  \                          |  |  :                           ,--. :/ |               __  ,-.
        /. ./|               |  | /\/                          :  :  :                           :  : ' /              ,' ,'/ /|
     .-'-. ' |    ,--.--.    :  : :                    ,---.   :  |  |,--.    ,---.      ,---.   |  '  /       ,---.   '  | |' |
    /___/ \: |   /       \   :  | |-,                 /     \  |  :  '   |   /     \    /     \  '  |  :      /     \  |  |   ,'
 .-'.. '   ' .  .--.  .-. |  |  : :/|                /    / '  |  |   /' :  /    /  |  /    / '  |  |   \    /    /  | '  :  /
/___/ \:     '   \__\/: . .  |  |  .'               .    ' /   '  :  | | | .    ' / | .    ' /   '  : |. \  .    ' / | |  | '
.   \  ' .\      ," .--.; |  '  : '            ___  '   ; :__  |  |  ' | : '   ;   /| '   ; :__  |  | ' \ \ '   ;   /| ;  : |
 \   \   ' \ |  /  /  ,.  |  |  | |         .'  .`| '   | '.'| |  :  :_:,' '   |  / | '   | '.'| '  : |--'  '   |  / | |  , ;
  \   \  |--"  ;  :   .'   \ |  : \      .'  .'   : |   :    : |  | ,'     |   :    | |   :    : ;  |,'     |   :    |  ---'
   \   \ |     |  ,     .-./ |  |,'   ,---, '   .'   \   \  /  `--''        \   \  /   \   \  /  '--'        \   \  /
    '---"       `--`---'     `--'     ;   |  .'       `----'                 `----'     `----'                `----'
                                      `---'

      
      
""")

# InsecureRequestWarning 경고 무시 (SSL 관련 경고 무시)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# global variables
waf_list = {}
error_site = []
user_id = ''
user_pw = ''

# Result class
class Result:
    def __init__(self, traffic, cpu, ram, disk):
        self.traffic = traffic
        self.cpu = cpu
        self.ram = ram
        self.disk = disk

    def __str__(self):
        return f"traffic : {self.traffic}, cpu : {self.cpu}, ram : {self.ram}, disk : {self.disk}"

# WAF_List 로드 및 User_id/pw 정보 확인
with open('waf_list.txt', 'r', encoding='UTF8') as f:
    user_id = f.readline().split(" : ")[1]
    user_pw = f.readline().split(" : ")[1]
    while True:
        line = f.readline()
        if not line: break
        name = line.split(" : ")[0]
        url = line.split(" : ")[1].strip()
        waf_list[name] = url

# WAF 상태 확인 function
def check_waf(site_name, url, pbar, lock, index):

    global user_id, user_pw

    # Waf 상태 결과
    result = Result(0, 0, 0, 0)
    waf_status_list = []
    count = 0

    # disk 사용량 임시 저장
    tmp_disk_data = 0

    # WAF 정보
    Host = url.split('//')[1]
    Origin = url
    Refer = url + '/login'

    # 세션
    session = requests.Session()
    session.verify = False

    # 헤더
    header = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'ko,en;q=0.9,en-US;q=0.8',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': Host,
        'Origin': Origin,
        'Referer': Refer,
        'X-Requested-With': 'XMLHttpRequest'
    }

    # 로그인에 필요한 정보
    login_url = url + "/login"
    login_payload = {
        "type": "password",
        "user_id": user_id,
        "user_pw": user_pw,
        "user_login": "true"
    }

    # waf 실시간 정보 요청
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime('%Y-%m-%d %I:%M:%S %p')
    waf_realtime_url = url + "/dashboard/summary/realTime"
    realtime_payload = {
        "current_time": formatted_time,
        "user_local_gmt": "+09:00"
    }

    for i in range(24):
        tmp_result = Result(0, 0, 0, 0)
        count += 1

        try:
            # 로그인 요청
            response = session.post(login_url, data=login_payload, headers=header)

            # waf 상태 요청
            response = session.post(waf_realtime_url, data=realtime_payload)

            # waf 상태 값 저장
            response_data = response.text[0:139].split(",")
            
            try: 
                tmp_result.traffic = int(response_data[3].replace("\"", "").split(":")[1])                
            except Exception as e:
                tmp_result.traffic = 0

            try:
                tmp_result.cpu = 100 - float(response_data[6].replace("\"", "").split(":")[1])
                tmp_result.ram = float(response_data[7].replace("\"", "").split(":")[1])
                tmp_result.disk = float(response_data[8].replace("\"", "").split(":")[1])
                
            except Exception as e :
                tmp_result.cpu = 0
                tmp_result.ram = 0
                tmp_result.disk = 0 
                count-=1
                pass

            waf_status_list.append(tmp_result)
            time.sleep(5)

        except requests.exceptions.RequestException as e:
            with open("error_log.txt", "a") as f: 
                f.write(f"{site_name}_waf : Error occurred : {e}\n")
                f.write(f"{site_name}_waf : WAF 상태를 확인해 주세요. \n")
                break

        # Process bar 1칸 업데이트
        pbar.update(1)

    for i in range(count):
        result.traffic += waf_status_list[i].traffic
        result.cpu += waf_status_list[i].cpu
        result.ram += waf_status_list[i].ram

        if tmp_disk_data <= waf_status_list[i].disk :
            tmp_disk_data = waf_status_list[i].disk        
        
    try :
        result.cpu = round(result.cpu / count, 0)
        result.ram = round(result.ram / count, 2)
        result.disk = tmp_disk_data
    # 예외 발생시 최신 데이터로 조회
    except Exception as e :
        result.cpu = waf_status_list[count-1].cpu
        result.ram = waf_status_list[count-1].ram
        result.disk = waf_status_list[count-1].disk

    # Lock을 사용해 순차적으로 파일에 기록
    with lock:
        with open("success_log.txt", "a") as f: 
            f.write(f"\n< {site_name}_waf >\n")
            if result.traffic < 0:
                f.write("트래픽 수치가 존재하지 않아 확인 부탁드립니다.\n")
            else:
                f.write(f"2분 traffic : {result.traffic}\n")
            f.write(f"CPU : {result.cpu}%\n")
            f.write(f"RAM : {result.ram}%\n")
            f.write(f"DISK : {result.disk}%\n")

# Multi Threading
def run_in_threads():
    threads = []
    pbar_list = []
    lock = threading.Lock()  # Lock 객체 생성

    for index, (site_name, url) in enumerate(waf_list.items()):
        padding = 25 - (len(site_name) + len('_WAF'))
        pbar = tqdm(total=24, desc=f"{site_name}_WAF{' '*padding}", ncols=100, position=len(pbar_list))
        pbar_list.append(pbar)

        thread = threading.Thread(target=check_waf, args=(site_name, url, pbar, lock, index))
        threads.append(thread)
        thread.start()
        time.sleep(5)
    
    # 모든 스레드가 완료될 때까지 대기
    for thread in threads:
        thread.join()

# 오늘 날짜 작성
with open("success_log.txt", "w") as f: 
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime('%Y-%m-%d %I:%M %p')
    f.write(f"Today : {formatted_time}\n")

# WAF_checking 시작
run_in_threads()

# 종료 전에 키보드 입력 받아 종료하기
print()
print("오류 발견하시면 문의 남겨주세요~~")
input("종료하려면 Enter 키를 눌러주세요.")