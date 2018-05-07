from ctypes import *
import os, sys, time, subprocess, requests, json, ctypes.wintypes

def download(url):
    file_name = os.path.basename(url)
    res = requests.get(url, stream=True)
    if res.status_code == 200:
        with open(file_name, 'wb') as file:
            for chunk in res.iter_content(chunk_size=1024):
                file.write(chunk)

def upload(url):
    files = {'file': open('dump.zip', 'rb')}
    r = requests.post(url, files=files)
    print(r.text)
 
if __name__ == '__main__':

    config_url = 'http://192.168.56.1:8080/config.json'
    target_url = 'http://192.168.56.1:8080/target/'
    up_url = 'http://192.168.56.1:8080/result'
    tools_url = 'http://192.168.56.1:8080/tools/'

    tools = ["hollows_hunter.exe", "pe-sieve.dll", "procdump.exe", "pssuspend.exe"]

    download(config_url)

    for tool_name in tools:
        download(tools_url+tool_name)

    with open('config.json', 'r') as outfile:
        config = json.load(outfile)

    target_url = target_url + config["target_file"]
    
    download(target_url)

    print(("%s download complete\n") % config["target_file"])

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

    os.mkdir("dump")

    print("dumping\n")

    if config["mode"] == "procdump":
         subprocess.call(["pssuspend.exe", config["target_file"], "/AcceptEula"])
         subprocess.call(["procdump.exe", "-ma", config["target_file"], "/AcceptEula"],cwd="dump")

    elif config["mode"] == "hollows_hunter":
        subprocess.call(["pssuspend.exe", config["target_file"]])
        subprocess.run(['cmd.exe', "/c", "start", "../hollows_hunter.exe"],cwd="dump")

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
                
    while(1):
        time.sleep(10)
        ret = subprocess.check_output("tasklist")
        if config["mode"] not in str(ret):
            break

    print("make zip\n")
    subprocess.run(['powershell', "compress-archive", "-Force", "dump", "dump.zip"])

    if os.path.isfile("dump.zip") == False:
        subprocess.run(['shutdown', "/p", "/f"])

    else:    
        upload(up_url)
        subprocess.run(['shutdown', "/p", "/f"])

