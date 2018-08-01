#!/usr/bin/env python3

import json, subprocess, requests, time, shutil, magic, os, uuid
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

    #post={}
    uid = str(uuid.uuid4())
    post = {"UUID":uid}

    InsertOneResult = collection.insert_one(post)

    print(InsertOneResult.inserted_id)

    json_data['target_file']=json_data['path'].split("/")[1]
    print(json.dumps(json_data, indent=4))

    with open('config.json', 'w') as outfile:
        json.dump(json_data, outfile)

    print({"status_code":0, "UUID":uid, "mesg":"Submission Success!"})

    print(subprocess.run(['virsh', "snapshot-revert", VM_NAME, "--current"]))

    while(1):
        vm_state = subprocess.check_output(["virsh", "domstate", VM_NAME])
        time.sleep(1)
        print (vm_state.decode('utf-8'))
        if "running" in str(vm_state.decode('utf-8')):
            cmd = [("./xmlrpc_client.py "+ uid)]
            subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
            break

    return jsonify(status_code=0, UUID=uid, mesg="Submission Success!")

@app.route('/upload', methods=['POST'])
def file_upload():
    f = request.files['file']
    filename = (f.filename)
    f.save(os.path.join(UPLOAD_FOLDER, filename))

    file_type = magic.from_file("target/"+filename)
    print(file_type)

    if ("DLL" in file_type) or (("PE32" or"PE32+") not in file_type):
            print("Invalid File Format!!\nOnly PE Format File (none dll)\n")
            return jsonify(status_code=1, mesg="Invalid File Format!!\nOnly PE Format File (none dll)\n")

    if (("PE32" or "PE32+") in file_type):
        root, ext = os.path.splitext("target/"+filename)
        if ext != "exe":
            os.rename("target/"+filename, root+".exe")
            filename=root+".exe"

    return jsonify(status_code=0, path=UPLOAD_FOLDER+filename)

@app.route('/result/<uuid>')
def show_result(uuid=None):
    uid= request.args.get('uuid')
    result = str(list(collection.find({u"UUID":uid}))[0])
    return jsonify(status_code=0, result=result)
    

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify(status_code=1, mesg='Not found'), 404)

if __name__ == '__main__':
    client = MongoClient('localhost', 27017)
    db = client.scan_database
    collection = db.scan_collection

    app.run(host='192.168.122.1', port=8080)
    

