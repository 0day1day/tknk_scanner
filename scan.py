import os, sys, argparse, shutil, json, subprocess, time, yara, glob, hashlib, datetime

parser = argparse.ArgumentParser()
parser.add_argument('-f', action="store", dest="target_file", help='input target file path')
parser.add_argument('-t', action="store", dest="time", type=float, default=False, help='input waiting time for unpack [default=180, MAX=600]')
parser.add_argument('-d', action="store_true", dest="procdump", default=False, help='Create a process memory dump using procdump.')
args = parser.parse_args()

times=180

now = datetime.datetime.today()
file_sha1 = str(hashlib.sha256(open(args.target_file,'rb').read()).hexdigest())

if(args.time):
    times = args.time

print ("time=%d" % (times))

config = {'target_file':args.target_file, 'time':times, 'procdump':args.procdump}

with open('config.json', 'w') as outfile:
    json.dump(config, outfile)

shutil.copy(args.target_file, "target/")

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
        print("Unpack fail\n")
        exit()

if os.path.isfile("result/dump.zip") == False:
    print("Unpack fail\n")
    exit()

else:
    subprocess.run(['unzip', "dump.zip"], cwd="result")   

rules = yara.compile('rules/index.yar')

result = {}

files = glob.glob("result/dump/**", recursive=True)

for f in files:
    if "exe" in f.rsplit(".", 1) or "dll" in f.rsplit(".", 1) or "dmp" in f.rsplit(".", 1):
        sha256_hash = str(hashlib.sha256(open(f,'rb').read()).hexdigest())
        print(sha256_hash)
        matches = rules.match(f)
        result.update({sha256_hash:{"detect_rule":str(matches), "name":f.rsplit("/", 1)[1], "file_name":args.target_file,
                      "time":times, "file_sha1":file_sha1,
                      "scan_time":str(now.strftime("%Y-%m-%d_%H:%M:%S"))}})

print (json.dumps(result, indent=4))

with open("result/dump/"+file_sha1+'.json', 'w') as outfile:
    json.dump(result, outfile)


os.rename("result/dump", "result/"+str(now.strftime("%Y-%m-%d_%H:%M:%S")))

os.remove("result/dump.zip")

os.remove("config.json")

