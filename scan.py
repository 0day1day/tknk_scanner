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
    return res.text
    
with open('config.json', 'r') as f:
    config = json.load(f)

result = []

now = datetime.datetime.today()
file_sha1 = str(hashlib.sha256(open(config['path'],'rb').read()).hexdigest())

rules = yara.compile('rules/index.yar')
matches = rules.match(config['path'])

try:
    shutil.move(config['path'], "target/")
except shutil.Error:
    pass  

print (config)

result.append({file_sha1:{"detect_rule":str(matches), "file_name":config['target_file'],
                      "time":config['time'], "scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))}})

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
        print("connection Error.")
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        break

    if status_code == "done":
        print(status_code)
        download("http://192.168.56.2:8080/dump.zip")
        try:
            shutil.move("dump.zip", "result/")

        except FileNotFoundError:
            print("Unpack fail\n")
            subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"])
            subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"])
            break

        print("dump finish")
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        break

    time.sleep(10)

    count = count + 1

    if count == 500:
        print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))
        print("Unpack timeout")
        break

if os.path.isfile("result/dump.zip") == False:
    print("Unpack fail\n")
    with open("result/"+ str(now.strftime("%Y-%m-%d_%H:%M:%S")) + "/" +file_sha1+'.json', 'w') as outfile:
            json.dump(result, outfile)
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
		result.append({sha256_hash:{"detect_rule":str(matches), "name":f.rsplit("/", 1)[1], "file_name":target_file,
		              "time":times, "file_sha1":file_sha1,
		              "scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))}})

print (json.dumps(result, indent=4))

with open("result/dump/"+file_sha1+'.json', 'w') as outfile:
    json.dump(result, outfile)

os.rename("result/dump/", "result/"+str(now.strftime("%Y-%m-%d_%H:%M:%S")))
os.remove("result/dump.zip")
os.remove("config.json")

