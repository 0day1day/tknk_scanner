#!/usr/bin/env python3

from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging, cgi, os, re, subprocess
from urllib.parse import urlparse
from ctypes import *
import sys, time, requests, json, ctypes.wintypes
from pathlib import Path

def dump():
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

    with open('status.exe', mode = 'w') as f:
      f.write('finish')


class S(SimpleHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if None != re.search('/status', self.path):
            f = self.send_head()
            status = f.read()
            print(status.decode('utf-8'))
            self.wfile.write("{}".format(status.decode('utf-8')).encode('utf-8'))  

        else:       
            f = self.send_head()
            if f:
                try:
                    self.copyfile(f, self.wfile)
                finally:
                    f.close()

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })

        self.send_response(200)
        self.end_headers()

        path = self.path.strip("/")
        if path == "dump_start":
            with open('status.exe', mode = 'w') as f:
                f.write('processing')
            subprocess.run(['cmd.exe', "/c", "start", "python", "dumper.py", "--dump"]) 
            return
        
        for field in form.keys():
            field_item = form[field]
            if field_item.filename:
                file_data = field_item.file.read()
                file_len = len(file_data)
                with open(field_item.filename, mode = 'wb') as f:
                    f.write(file_data)

                self.wfile.write("upload {}".format(field_item.filename).encode('utf-8'))
            else:
                self.wfile.write("{}=".format(field).encode('utf-8'))
                self.wfile.write("{}".format(form[field].value).encode('utf-8'))                
        return

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('192.168.56.2', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        if argv[1] == "--dump":
            dump()
    else:
        run()
