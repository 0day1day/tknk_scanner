#!/usr/bin/env python3

import os, sys, shutil, json, subprocess, time, yara, glob, hashlib, datetime, requests

def download(url):
    file_name = os.path.basename(url)
    res = requests.get(url, stream=True)
    if res.status_code == 200:
        with open(file_name, 'wb') as file:
            for chunk in res.iter_content(chunk_size=1024):
                file.write(chunk)
    return res.status_code

def upload(url, filename):
    files = {'file': open(filename, 'rb')}
    r = requests.post(url, files=files)
    print (r.text)
    return r.text

def dump(url):
    print("dump_start")
    r = requests.post(url)
    return

def state(url):
    res = requests.get(url, stream=True)
 
    if res.status_code == 404:
        return res.status_code

    return res.text
    
with open('config.json', 'r') as f:
    config = json.load(f)

result = {"result":
            {"unpack":False,
             "comment":[]},
          "scans":[]
         }

now = datetime.datetime.today()
file_sha256 = str(hashlib.sha256(open(config['path'],'rb').read()).hexdigest())

rules = yara.compile('rules/index.yar')
matches = rules.match(config['path'])

try:
    shutil.move(config['path'], "target/")
except shutil.Error:
    pass  

print (config)

result['scans'].append({"sha256":file_sha256, "detect_rule":str(matches), "file_name":config['target_file'],
                      "time":config['time'], "scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))})

os.mkdir("result/" + str(now.strftime("%Y-%m-%d_%H:%M:%S")))

print(subprocess.run(['VBoxManage', "startvm", "win10"]))

while(1):
    vm_state = subprocess.check_output(['VBoxManage', "list", "runningvms"])
    if "win10" in str(vm_state):
        up_url = "http://192.168.56.2:8080/"
        upload(up_url, "config.json")
        tools = ["tools/hollows_hunter.exe", "tools/pe-sieve.dll", "tools/procdump.exe", "tools/pssuspend.exe"]
        for tool_name in tools:
            upload(up_url, tool_name)
        upload(up_url, "target/" + config['target_file'])
        dump("http://192.168.56.2:8080/dump_start")
        break

count = 0

while(1):
    try: 
        status_code = state("http://192.168.56.2:8080/status") 
    except OSError:
        print("connection Error")
        result['result']["comment"].append("connection Error")
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        break

    if status_code == 404:
        print("status code: 404")
        result['result']["comment"].append("connection Error")
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        break

    if status_code == "done":
        print(status_code)
        status_code = download("http://192.168.56.2:8080/dump.zip")
        if status_code == 200:
            shutil.move("dump.zip", "result/")
        else:
            print("dump does not exist\n")
            result['result']["comment"].append("dump does not exist")
            subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"])
            subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"])
            break

        print("dump finish")
        result['result']["unpack"] = True
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        break

    time.sleep(10)

    count = count + 1

    if count == 60:
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        print("Unpack timeout")
        result['result']["comment"].append("Unpack timeout")
        break

if result['result']["unpack"] == False:
    print("Unpack fail\n")
    with open("result/"+ str(now.strftime("%Y-%m-%d_%H:%M:%S")) + "/" +file_sha256+'.json', 'w') as outfile:
            json.dump(result, outfile, indent=4)
    print (json.dumps(result, indent=4))
    os.remove("config.json")
    exit()

else:
    subprocess.run(['unzip', "dump.zip"], cwd="result")   

files = glob.glob("result/dump/**", recursive=True)

for f in files:
	if "exe" in f.rsplit(".", 1) or "dll" in f.rsplit(".", 1) or "dmp" in f.rsplit(".", 1):
		sha256_hash = str(hashlib.sha256(open(f,'rb').read()).hexdigest())
		matches = rules.match(f)
		result['scans'].append({"sha256":sha256_hash, "detect_rule":str(matches), "file_name":f.rsplit("/", 1)[1],
		              "time":config['time'],"scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))})

print (json.dumps(result, indent=4))

with open("result/dump/"+file_sha256+'.json', 'w') as outfile:
    json.dump(result, outfile, indent=4)

os.rename("result/dump/", "result/"+str(now.strftime("%Y-%m-%d_%H:%M:%S")))
os.remove("result/dump.zip")
os.remove("config.json")

