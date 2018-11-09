#!/usr/bin/env python3

from xmlrpc.server import SimpleXMLRPCServer
import xmlrpc.client
from ctypes import *
import sys, time, json, ctypes.wintypes, os, subprocess
from pathlib import Path

#Microsoft types to ctypes for clarity
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
LONG      = c_long
DWORD64   = c_uint64
PWCHAR    = c_wchar_p
DWORD_PTR = c_uint64
BOOL      = c_bool
DWORD_PTR_P= POINTER(c_uint64)

# Constants
DEBUG_PROCESS         = 0x00000001
CREATE_NEW_CONSOLE    = 0x00000010

# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS   = 0x001F03FF

kernel32 = windll.kernel32
advapi32 = windll.advapi32

# Structures for CreateProcessW() function
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]

################################################

def download_file():
     with open("dump.zip", "rb") as handle:
        return xmlrpc.client.Binary(handle.read())


def upload_file(arg, filename):
    print ("upload... " + filename)
    with open(filename, "wb") as handle:
        handle.write(arg.data)
        return True

def dump(config):
    os.mkdir("dump")

    subprocess.call(['cmd.exe', "/c", "start", "pythonw", "mouse_emu.pyw"])

    if config["mode"] == "diff":
        Psapi = ctypes.WinDLL('Psapi.dll')
        EnumProcesses = Psapi.EnumProcesses
        EnumProcesses.restype = ctypes.wintypes.BOOL

        ProcessIds = (ctypes.wintypes.DWORD*512)()
        cb = ctypes.sizeof(ProcessIds)
        BytesReturned = ctypes.wintypes.DWORD()

        EnumProcesses(ctypes.byref(ProcessIds), cb, ctypes.byref(BytesReturned))
        src_set = set(ProcessIds)

    #subprocess.call(['cmd.exe', "/c", "start", config['target_file']])

    path_to_exe=config['target_file']

    creation_flags = CREATE_NEW_CONSOLE 
    startupinfo         = STARTUPINFO()
    process_information = PROCESS_INFORMATION()
    startupinfo.dwFlags     = 0x1
    startupinfo.wShowWindow = 0x0
    startupinfo.cb = sizeof(startupinfo)
    
    if kernel32.CreateProcessW(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):

        print ("[*] Launched the process!")
        print ("[*] The Process ID is: %d" % process_information.dwProcessId)
        PID = process_information.dwProcessId

    else:    
        print ("[*] Error with error code %d." % kernel32.GetLastError())
        exit()

    print(("wait for unpack %d seconds\n") % config["time"])
        
    time.sleep(config["time"])

    print("dumping\n")

    if config["mode"] == "procdump":
        subprocess.call(["pssuspend.exe", config["target_file"], "/AcceptEula"])
        subprocess.call(["procdump.exe", "-ma", PID, "/AcceptEula"],cwd="dump")

    elif config["mode"] == "hollows_hunter":
        subprocess.call(["pssuspend.exe", config["target_file"], "/AcceptEula"])
        subprocess.call(["hollows_hunter.exe"],cwd="dump")

    elif config["mode"] == "diff":
        EnumProcesses(ctypes.byref(ProcessIds), cb, ctypes.byref(BytesReturned))
        tag_set = set(ProcessIds)

        diff_ProcessIds = list(src_set ^ tag_set)

        new_ProcessIds = []

        for pid in diff_ProcessIds:
            try:
                proc_state = subprocess.check_output(["pssuspend.exe", str(pid), "/AcceptEula"])
                if "suspended." in str(proc_state):
                    new_ProcessIds.append(pid)
            except subprocess.CalledProcessError:
                pass
        for pid in new_ProcessIds:
            subprocess.call(["procdump.exe", "-ma", str(pid), "/AcceptEula"],cwd="dump")

    elif config["mode"] == "scylla":
        print("##TODO")

    print("make zip\n")
    subprocess.call(['powershell', "compress-archive", "-Force", "dump", "dump.zip"])

################################################

if __name__ == '__main__':
    server = SimpleXMLRPCServer(('0.0.0.0', 8000), allow_none=True)
    print ("Listening on port 8000...")
    server.register_function(download_file, 'download_file')
    server.register_function(upload_file, 'upload_file')
    server.register_function(dump, 'dump')
    server.serve_forever()
