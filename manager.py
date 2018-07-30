#!/usr/bin/env python3

import logging, json, subprocess, requests, time, shutil, magic, os
from pymongo import MongoClient
from flask import Flask, jsonify, request, url_for, abort, Response

VM_NAME="win10"
UPLOAD_FOLDER="target/" 

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def start_analyze():
    if request.headers['Content-Type'] != 'application/json':
        print(request.headers['Content-Type'])
        return jsonify(res='error'), 400

    json_data = request.json

    post = {}
    InsertOneResult = collection.insert_one(post)

    print(InsertOneResult.inserted_id)

    print(json.dumps(json_data, indent=4))

    with open('config.json', 'w') as outfile:
        json.dump(json_data, outfile)

    print({"status_code":0, "UUID":str(InsertOneResult.inserted_id), "msg":"Submission Success!"})

    print(subprocess.run(['virsh', "snapshot-revert", VM_NAME, "--current"]))

    while(1):
        vm_state = subprocess.check_output(["virsh", "domstate", VM_NAME])
        time.sleep(1)
        print (vm_state.decode('utf-8'))
        if "running" in str(vm_state.decode('utf-8')):
            cmd = [("./xmlrpc_client.py "+str(InsertOneResult.inserted_id))]
            subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
            break

    return jsonify(status_code=0, UUID=str(InsertOneResult.inserted_id), msg="Submission Success!")

@app.route('/file', methods=['POST'])
def file_upload():
    f = request.files['file']
    filename = (f.filename)
    f.save(os.path.join(UPLOAD_FOLDER, filename))

    file_type = magic.from_file("target/"+filename)
    print(file_type)

    if ("DLL" in file_type) or (("PE32" or"PE32+") not in file_type):
            print("Invalid File Format!!\nOnly PE Format File (none dll)\n")
            return jsonify(status_code=1, UUID=None, msg="Invalid File Format!!\nOnly PE Format File (none dll)\n")

    if (("PE32" or "PE32+") in file_type):
        root, ext = os.path.splitext("target/"+filename)
        if ext != "exe":
            print("rename: "+root+".exe")
            os.rename("target/"+filename, root+".exe")
            filename=root+".exe"

    return jsonify(status_code=0, path=UPLOAD_FOLDER+filename)

@app.route('/result', methods=['GET'])
def show_result():
    #Todo
    pass

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == '__main__':
    client = MongoClient('localhost', 27017)
    db = client.scan_database
    collection = db.scan_collection

    app.run(host='192.168.122.1', port=8080)
    

