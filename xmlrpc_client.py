#!/usr/bin/env python3

import xmlrpc.client
import os, sys, shutil, json, subprocess, time, yara, glob, hashlib, datetime, requests
from pymongo import MongoClient
from bson.objectid import ObjectId

vm_url = "http://192.168.122.2:8000/"
vm_name = "win10"

def download():
    proxy = xmlrpc.client.ServerProxy(vm_url)
    with open("dump.zip", "wb") as handle:
        try:
            handle.write(proxy.download_file().data)
            return True

        except xmlrpc.client.Fault:
            print(sys.exc_info())
            return sys.exc_info()

            
def upload(filename):
    proxy = xmlrpc.client.ServerProxy(vm_url)
    with open(filename, "rb") as handle:
        binary_data = xmlrpc.client.Binary(handle.read())
    if "/" in filename:
        filename = filename.rsplit("/", 1)[1]
    print("upload..." + filename)
    proxy.upload_file(binary_data, filename)

def dump():
    proxy = xmlrpc.client.ServerProxy(vm_url)
    proxy.dump()

def vm_down():
    print(subprocess.call(['virsh', "destroy", vm_name]))


args = sys.argv

#db connect
client = MongoClient('localhost', 27017)
db = client.scan_database

collection = db.scan_collection

#read config
with open('config.json', 'r') as f:
    config = json.load(f)

#make report format
now = datetime.datetime.today()
result = {"result":{"detail":"", "is_success":False},
          "run_time":config['time'], 
          "mode":config['mode'],
          "timestamp":str(now.isoformat()),
          "scans":[]
         }

file_sha256 = str(hashlib.sha256(open(config['path'],'rb').read()).hexdigest())


rules = yara.compile('index.yar')
matches = rules.match(config['path'])

result['scans'].append({"sha256":file_sha256, "detect_rule":list(map(str,matches)), "file_name":config['target_file']})

os.mkdir("result/" + str(now.strftime("%Y-%m-%d_%H:%M:%S")))

upload("config.json")
tools = ["tools/hollows_hunter.exe", "tools/pe-sieve.dll", "tools/procdump.exe", "tools/pssuspend.exe", "tools/mouse_emu.exe"]

for tool_name in tools:
    upload(tool_name)

upload("target/" + config['target_file'])

dump()

ret = download() 
 
if ret == True:
    shutil.move("dump.zip", "result/")
    print("dump finish")
    result["result"]["is_success"] = True

else:
    print("dump does not exist\n")
    result["result"]["is_success"] == False
    result["result"]["detail"] = "dump does not exist"  

vm_down()

if result["result"]["is_success"] == False:
    print("Unpack fail\n")
    with open("result/"+ str(now.strftime("%Y-%m-%d_%H:%M:%S")) + "/" +file_sha256+'.json', 'w') as outfile:
            json.dump(result, outfile, indent=4)
    print (json.dumps(result, indent=4))
    os.remove("config.json")
    collection.update({'_id':ObjectId(args[1])},result)
    exit()

elif result["result"]["is_success"] == True:

    subprocess.run(['unzip', "dump.zip"], cwd="result")   

files = glob.glob("result/dump/**", recursive=True)

for f in files:
    if "exe" in f.rsplit(".", 1) or "dll" in f.rsplit(".", 1) or "dmp" in f.rsplit(".", 1):
	    sha256_hash = str(hashlib.sha256(open(f,'rb').read()).hexdigest())
	    matches = rules.match(f)
	    result['scans'].append({"sha256":sha256_hash, "detect_rule":list(map(str,matches)), "file_name":f.rsplit("/", 1)[1]})

print (json.dumps(result, indent=4))

with open("result/dump/"+file_sha256+'.json', 'w') as outfile:
    json.dump(result, outfile, indent=4)

os.rename("result/dump/", "result/"+str(now.strftime("%Y-%m-%d_%H:%M:%S")))
os.remove("result/dump.zip")
os.remove("config.json")

collection.update({'_id':ObjectId(args[1])},result)

