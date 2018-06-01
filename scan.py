#!/usr/bin/env python3

import os, sys, shutil, json, subprocess, time, yara, glob, hashlib, datetime, requests
from pymongo import MongoClient
from bson.objectid import ObjectId

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
  
def vm_down():
    print(subprocess.call(['VBoxManage', "controlvm", "win10", "poweroff"]))
    print(subprocess.call(['VBoxManage', "snapshot", "win10", "restorecurrent"]))


args = sys.argv
print (args[1])
print (type(args[1]))

#db connect
client = MongoClient('localhost', 27017)
db = client.scan_database

collection = db.scan_collection

#read config
with open('config.json', 'r') as f:
    config = json.load(f)

#make report format
now = datetime.datetime.today()

result = {"status":{"detail":"", "is_success":False},
          "run_time":config['time'], 
          "mode":config['mode'],
          "timestamp":str(now.isoformat()),
          "scans":[]
         }

vm_url = "http://192.168.56.2:8080/"

file_sha256 = str(hashlib.sha256(open(config['path'],'rb').read()).hexdigest())

rules = yara.compile('yara/index.yar')
matches = rules.match(config['path'])

try:
    shutil.move(config['path'], "target/")
except shutil.Error:
    pass  

result['scans'].append({"sha256":file_sha256, "detect_rule":matches, "file_name":config['target_file']})

os.mkdir("result/" + str(now.strftime("%Y-%m-%d_%H:%M:%S")))

print(subprocess.run(['VBoxManage', "startvm", "win10"]))

while(1):
    vm_state = subprocess.check_output(['VBoxManage', "list", "runningvms"])
    if "win10" in str(vm_state):
        up_url = vm_url
        upload(up_url, "config.json")
        tools = ["tools/hollows_hunter.exe", "tools/pe-sieve.dll", "tools/procdump.exe", "tools/pssuspend.exe"]
        for tool_name in tools:
            upload(up_url, tool_name)
        upload(up_url, "target/" + config['target_file'])
        dump(vm_url + "dump_start")
        break

count = 0

while(1):
    try: 
        status_code = state(vm_url + "status.exe") 
    except OSError:
        print("connection Error")
        result["status"]["detail"] = "connection Error"
        vm_down()
        break

    if status_code == 404:
        print("status code: 404")
        result["status"]["detail"] = "connection Error"
        vm_down()
        break

    if status_code == "finish":
        print(status_code)
        status_code = download(vm_url + "dump.zip")
        if status_code == 200:
            shutil.move("dump.zip", "result/")
        else:
            print("dump does not exist\n")
            result["status"]["detail"] = "dump does not exist"
            vm_down()
            break

        print("dump finish")
        result["status"]["is_success"] = True
        vm_down()
        break

    time.sleep(10)

    count = count + 1

    if count == 60:
        vm_down()
        print("Unpack timeout")
        result["status"]["detail"] = "Unpack timeout"
        break

if result["status"]["is_success"] == False:
    print("Unpack fail\n")
    with open("result/"+ str(now.strftime("%Y-%m-%d_%H:%M:%S")) + "/" +file_sha256+'.json', 'w') as outfile:
            json.dump(result, outfile, indent=4)
    print (json.dumps(result, indent=4))
    os.remove("config.json")
    collection.update({'_id':ObjectId(args[1])},result)
    print(list(collection.find()))
    exit()

else:
    subprocess.run(['unzip', "dump.zip"], cwd="result")   

files = glob.glob("result/dump/**", recursive=True)

for f in files:
	if "exe" in f.rsplit(".", 1) or "dll" in f.rsplit(".", 1) or "dmp" in f.rsplit(".", 1):
		sha256_hash = str(hashlib.sha256(open(f,'rb').read()).hexdigest())
		matches = rules.match(f)
		result['scans'].append({"sha256":sha256_hash, "detect_rule":matches, "file_name":f.rsplit("/", 1)[1]})

print (json.dumps(result, indent=4))

with open("result/dump/"+file_sha256+'.json', 'w') as outfile:
    json.dump(result, outfile, indent=4)

os.rename("result/dump/", "result/"+str(now.isoformat()))
os.remove("result/dump.zip")
os.remove("config.json")

collection.update({'_id':ObjectId(args[1])},result)

print(list(collection.find()))


