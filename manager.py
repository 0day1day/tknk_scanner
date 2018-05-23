#!/usr/bin/env python3

from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging, json, subprocess, requests

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
            json_data.update({'target_file':target_file})
        else:
            json_data.update({'target_file':json_data['path']})

        print(json.dumps(json_data, indent=4))

        with open('config.json', 'w') as outfile:
            json.dump(json_data, outfile)

        #subprocess.run(['gnome-terminal', "-e", "bash -c './scan.py'"])
        subprocess.run(["./scan.py"])

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('192.168.56.1', port)
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

    run()
