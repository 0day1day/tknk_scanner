import xmlrpc.client
import os, sys, shutil, json, subprocess, time, yara, glob, hashlib, datetime, requests
from pymongo import MongoClient
from bson.objectid import ObjectId

vm_url = "http://192.168.56.2:8080/"

proxy = xmlrpc.client.ServerProxy(vm_url)

def download():
    with open("pd64.exe", "wb") as handle:
        handle.write(proxy.download_file().data)

def upload(filename):
    with open(filename, "rb") as handle:
        binary_data = xmlrpc.client.Binary(handle.read())
    proxy.upload_file(binary_data, "test.py")

def dump():
    proxy.dump()

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

while(1):
    vm_state = subprocess.check_output(['VBoxManage', "list", "runningvms"])
    if "win10" in str(vm_state):
        up_url = vm_url
        upload("config.json")
        tools = ["tools/hollows_hunter.exe", "tools/pe-sieve.dll", "tools/procdump.exe", "tools/pssuspend.exe"]
        for tool_name in tools:
            upload(tool_name)
        upload(up_url, "target/" + config['target_file'])
        dump()
        break



