#!/usr/bin/env python3

from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging, json, subprocess, requests, time, shutil, magic, os
from pymongo import MongoClient

vm_name = "win10"

class S(SimpleHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=UTF-8')
        self.end_headers()

    def do_POST(self):
        content_len = int(self.headers.get('content-length'))
        requestBody = self.rfile.read(content_len).decode('UTF-8')
        #print('requestBody=' + requestBody)
        json_data = json.loads(requestBody)
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        self.end_headers()

        if "/" in json_data['path']:
            target_file = json_data['path'].rsplit("/", 1)[1]
            json_data['target_file'] = target_file

        file_type = magic.from_file("target/"+json_data['target_file'])
        print(file_type)

        if ("DLL" in file_type) or (("PE32" or"PE32+") not in file_type):
            print("Invalid File Format!!\nOnly PE Format File (none dll)\n")
            self.wfile.write((str({"status_code":1, "UUID":None, "msg":"Invalid File Format!!\nOnly PE Format File (none dll)\n"})).encode('utf-8'))
            return 

        if (("PE32" or "PE32+") in file_type):
            root, ext = os.path.splitext("target/"+json_data['target_file'])
            if ext != "exe":
                print("rename: "+root+".exe")
                os.rename("target/"+json_data['target_file'], root+".exe")
                json_data.update({'target_file':json_data['target_file'].split(".")[0]+".exe"})
                json_data.update({'path':json_data['path'].split(".")[0]+".exe"})

        post = {}
        InsertOneResult = collection.insert_one(post)

        print(InsertOneResult.inserted_id)

        print(json.dumps(json_data, indent=4))

        with open('config.json', 'w') as outfile:
            json.dump(json_data, outfile)

        self.wfile.write((str({"status_code":0, "UUID":str(InsertOneResult.inserted_id), "msg":"Submission Success!"})).encode('utf-8'))

        print(subprocess.run(['virsh', "snapshot-revert", vm_name, "--current"]))

        while(1):
            vm_state = subprocess.check_output(["virsh", "domstate", vm_name])
            time.sleep(1)
            print (vm_state.decode('utf-8'))
            if "running" in str(vm_state.decode('utf-8')):
                cmd = [("./xmlrpc_client.py "+str(InsertOneResult.inserted_id))]
                subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
                break

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('192.168.122.1', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    client = MongoClient('localhost', 27017)
    db = client.scan_database

    collection = db.scan_collection

    run()
