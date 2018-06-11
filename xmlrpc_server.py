from xmlrpc.server import SimpleXMLRPCServer
import xmlrpc.client

vm_ipaddr = "192.168.56.2"

def download_file():
     with open("pd64.exe", "rb") as handle:
         return xmlrpc.client.Binary(handle.read())

def upload_file(arg, filename):
        with open(filename, "wb") as handle:
            print(arg)
            handle.write(arg.data)
            return True

def dump():


server = SimpleXMLRPCServer((vm_ipaddr, 8000))
print ("Listening on port 8000...")
server.register_function(download_file, 'download_file')
server.register_function(upload_file, 'upload_file')
server.register_function(dump, 'dump')
server.serve_forever()
