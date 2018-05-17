from ctypes import *
import os, sys, time, subprocess, requests, json, ctypes.wintypes
from pathlib import Path

os.mkdir("dump")

with open('config.json', 'r') as outfile:
    config = json.load(outfile)

if config["mode"] == "diff":
    Psapi = ctypes.WinDLL('Psapi.dll')
    EnumProcesses = Psapi.EnumProcesses
    EnumProcesses.restype = ctypes.wintypes.BOOL

    ProcessIds = (ctypes.wintypes.DWORD*512)()
    cb = ctypes.sizeof(ProcessIds)
    BytesReturned = ctypes.wintypes.DWORD()

    EnumProcesses(ctypes.byref(ProcessIds), cb, ctypes.byref(BytesReturned))
    src_set = set(ProcessIds)

subprocess.run(['cmd.exe', "/c", "start", config['target_file']])

print(("wait for unpack %d seconds\n") % config["time"])
    
time.sleep(config["time"])

print("dumping\n")

if config["mode"] == "procdump":
     subprocess.call(["pssuspend.exe", config["target_file"], "/AcceptEula"])
     subprocess.call(["procdump.exe", "-ma", config["target_file"], "/AcceptEula"],cwd="dump")

elif config["mode"] == "hollows_hunter":
    subprocess.call(["pssuspend.exe", config["target_file"]])
    subprocess.call(["hollows_hunter.exe"],cwd="dump")

elif config["mode"] == "diff":
    EnumProcesses(ctypes.byref(ProcessIds), cb, ctypes.byref(BytesReturned))
    tag_set = set(ProcessIds)

    diff_ProcessIds = list(src_set ^ tag_set)
    print(diff_ProcessIds)

    new_ProcessIds = []

    for pid in diff_ProcessIds:
        try:
            proc_state = subprocess.check_output(["pssuspend.exe", str(pid), "/AcceptEula"])
            if "suspended." in str(proc_state):
                new_ProcessIds.append(pid)
        except subprocess.CalledProcessError:
            print(pid)
    print(new_ProcessIds)
    for pid in new_ProcessIds:
        subprocess.call(["procdump.exe", "-ma", str(pid), "/AcceptEula"],cwd="dump")

print("make zip\n")
subprocess.call(['powershell', "compress-archive", "-Force", "dump", "dump.zip"])

with open('status', mode = 'w') as f:
  f.write('done')

#if os.path.isfile("dump.zip") == False:
#    subprocess.call(['shutdown', "/p", "/f"])
#
#else:    
#    upload(up_url)
#    subprocess.call(['shutdown', "/p", "/f"])
