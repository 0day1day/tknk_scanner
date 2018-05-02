#!/usr/bin/env python3

import os, sys, argparse, shutil, json, subprocess, time, yara, glob, hashlib, datetime

parser = argparse.ArgumentParser()
parser.add_argument('-f', action="store", dest="target_file", help='input target file path')
parser.add_argument('-t', action="store", dest="time", type=float, default=False, help='input waiting time for unpack [default=180, MAX=600]')
parser.add_argument('-m', action="store", dest="mode", help='[hollows_hunter, procdump]')
args = parser.parse_args()

times=180
result = {}

now = datetime.datetime.today()
file_sha1 = str(hashlib.sha256(open(args.target_file,'rb').read()).hexdigest())

rules = yara.compile('rules/index.yar')
matches = rules.match(args.target_file)

if(args.time):
    times = args.time

print ("time=%d" % (times))

result.update({file_sha1:{"detect_rule":str(matches), "file_name":args.target_file,
                      "time":times, "scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))}})

if "/" in args.target_file:
    target_file = args.target_file.rsplit("/", 1)[1]
else:
    target_file = args.target_file

config = {'target_file':target_file, 'time':times, 'mode':args.mode}
print (config)

with open('config.json', 'w') as outfile:
    json.dump(config, outfile)

try:
    shutil.move(args.target_file, "target/")
except shutil.Error:
    pass

os.mkdir("result/" + str(now.strftime("%Y-%m-%d_%H:%M:%S")))

print(subprocess.run(['VBoxManage', "startvm", "win10"]))

time.sleep(times + 60)

count = 0

while(1):
    vm_state = subprocess.check_output(['VBoxManage', "list", "runningvms"])
    if "win10" not in str(vm_state):
        print("dump finish")
        print(subprocess.run(['VBoxManage', "snapshot", "win10", "restore", "run_kicker"]))
        break

    time.sleep(10)

    count = count + 1

    if count == 60:
        print(subprocess.run(['VBoxManage', "controlvm", "win10", "poweroff"]))
        print(subprocess.run(['VBoxManage', "snapshot", "win10", "restore", "run_kicker"]))
        print("Unpack timeout")
        break

if os.path.isfile("result/dump.zip") == False:
    print("Unpack fail\n")
    with open("result/"+ str(now.strftime("%Y-%m-%d_%H:%M:%S")) + "/" +file_sha1+'.json', 'w') as outfile:
            json.dump(result, outfile)
    os.remove("config.json")
    exit()

else:
    subprocess.run(['unzip', "dump.zip"], cwd="result")   

files = glob.glob("result/dump/**", recursive=True)

for f in files:
	if "exe" in f.rsplit(".", 1) or "dll" in f.rsplit(".", 1) or "dmp" in f.rsplit(".", 1):
		sha256_hash = str(hashlib.sha256(open(f,'rb').read()).hexdigest())
		matches = rules.match(f)
		result.update({sha256_hash:{"detect_rule":str(matches), "name":f.rsplit("/", 1)[1], "file_name":target_file,
		              "time":times, "file_sha1":file_sha1,
		              "scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))}})

print (json.dumps(result, indent=4))

with open("result/dump/"+file_sha1+'.json', 'w') as outfile:
    json.dump(result, outfile)

os.rename("result/dump/", "result/"+str(now.strftime("%Y-%m-%d_%H:%M:%S")))
os.remove("result/dump.zip")
os.remove("config.json")

