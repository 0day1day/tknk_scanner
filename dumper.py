#!/usr/bin/env python3
"""
Very simple HTTP server in python for logging requests
Usage::
    ./dumper.py [<port>]
"""
from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging, cgi, os, re, subprocess
from urllib.parse import urlparse

class S(SimpleHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if None != re.search('/status', self.path):
            self.send_head()
            self.wfile.write("{}\n".format(self.path).encode('utf-8'))  
            #self.send_response(200)
            #self.send_header('Content-type','text/html')
            #self.end_headers()
        
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
            subprocess.run(['cmd.exe', "/c", "start", "python", "dump.py"]) 
            return
        
        for field in form.keys():
            field_item = form[field]
            if field_item.filename:
                file_data = field_item.file.read()
                file_len = len(file_data)
                with open(field_item.filename, mode = 'wb') as f:
                    f.write(file_data)

                self.wfile.write("upload {}\n".format(field_item.filename).encode('utf-8'))
            else:
                self.wfile.write("{}=".format(field).encode('utf-8'))
                self.wfile.write("{}\n".format(form[field].value).encode('utf-8'))                
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
        run(port=int(argv[1]))
    else:
        run()
