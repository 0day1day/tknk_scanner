#!/usr/bin/env python3

import json, subprocess, requests, time, shutil, magic, os, uuid
from pathlib import Path
from pymongo import MongoClient
from flask import Flask, jsonify, request, url_for, abort, Response, make_response

VM_NAME="win10"
UPLOAD_FOLDER="target/" 

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def start_analyze():
    if request.headers['Content-Type'] != 'application/json':
        print(request.headers['Content-Type'])
        return jsonify(status_code=2, mesg="Content-Type Error.")

    with open("state.json", 'r') as f:
        state = json.load(f)

    if state['state'] == 1:
        return jsonify(status_code=1, mesg="It is processing now. Wait for analysis.")
    elif state['state'] == 0:
        state['state'] = 1
        with open("state.json", 'w') as f:
            json.dump(state, f)

    json_data = request.json

    #post={}
    uid = str(uuid.uuid4())
    post = {"UUID":uid}

    collection.insert_one(post)

    json_data['target_file']=json_data['path'].split("/")[1]
    print(json.dumps(json_data, indent=4))
    with open('config.json', 'w') as outfile:
        json.dump(json_data, outfile)

    cmd=[("virsh snapshot-revert " + VM_NAME + " --current")]
    p = (subprocess.Popen(cmd, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True))
    print("----------------")
    output = p.stderr.read().decode('utf-8')
    print(output)

    if "busy" in output:
        state={"state":0}
        with open("state.json", 'w') as f:
            json.dump(state, f)
        return jsonify(status_code=2, mesg="failed to initialize KVM: Device or resource busy")
        
    elif "Domain" in output:
        state={"state":0}
        with open("state.json", 'w') as f:
            json.dump(state, f)
        return jsonify(status_code=2, mesg="Domain snapshot not found: the domain does not have a current snapshot")

    cmd = [("./xmlrpc_client.py "+ uid)]
    subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)

    return jsonify(status_code=0, UUID=uid, mesg="Submission Success!")

@app.route('/upload', methods=['POST'])
def file_upload():
    f = request.files['file']
    filename = (f.filename)
    f.save(os.path.join(UPLOAD_FOLDER, filename))

    file_type = magic.from_file("target/"+filename)
    print(file_type)

    if ("DLL" in file_type) or (("PE32" or"PE32+") not in file_type):
            print("Invalid File Format!! Only PE Format File(none dll).")
            return jsonify(status_code=2, mesg="Invalid File Format!! Only PE Format File(none dll).")

    if (("PE32" or "PE32+") in file_type):
        path = Path("target/"+filename)
        if path.suffix != "exe":
            os.rename("target/"+path.name, path.stem+".exe")
            filename=path.stem+".exe"

    return jsonify(status_code=0, path=UPLOAD_FOLDER+filename)

@app.route('/result/<uuid>')
def show_result(uuid=None):
    print(uuid)
    #uid= request.args.get('uuid')
    #print(uid)
    result = list(collection.find({u"UUID":uuid}))[0]
    result.pop('_id')

    return jsonify(status_code=0, result=result)
    

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify(status_code=2, mesg='Not found.'), 404)

if __name__ == '__main__':
    client = MongoClient('localhost', 27017)
    db = client.scan_database
    collection = db.scan_collection

    state={"state":0}
    with open("state.json", 'w') as f:
        json.dump(state, f)

    app.run(host='192.168.122.1', port=8000)
    

