tknk_scanner
===

tknk_scanner is community-based integrated malware identification system. You can scan the original code of malware with your own yara rules just by submit malware of PE format to tknk_scanner. Normally, you need to scan using yara after dumping the original code with a debugger etc for obfuscated malware binaries.This process is complicated and requires well-equipped malware analyzing environment. tknk_scanner can be easily identify malware families by automating that process. We integrate open source community based tools and freeware to achieve them. In this way, tknk_scanner can support surface analysis of SOC operators, CSIRT members and malware analysts.


## Features
* Automatic identification and classification of malware
    * Scan the original code of malware with yara.
* Dumps original code of malware
    * You can easily get the original code. 
* User-friendly Web-UI
    * Users can submit malware and check scan results using the Web-UI.


## Requirements
* python 3.5 or later
* yara-python 3.7.0
* Web Server (e.g. xxxx)

## Installation

### Preparing the Host
1. git clone *repository_url*
2. Run `setup/setup.sh`
3. Install yara-python
  ```
$ git clone --recursive https://github.com/VirusTotal/yara-python
$ cd yara-python
$ python setup.py build
$ sudo python setup.py install
```
4. Edit tknk.conf
    * vm_name
    * vm_url
5. Download Tools and copy to `tools/`
    * [hollows_hunter](https://github.com/hasherezade/hollows_hunter)
    * [PsSuspend](https://docs.microsoft.com/en-us/sysinternals/downloads/pssuspend)
    * [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
6. Set yara rules  
  Save yara rules in "rules" folder. You need to add the rule to index.yar.  
  We have a script. Please add a path to `index_gen.py` as follows.  
  ```
  paths = []
  ```
  And run `python3 index_gen.py`.


### Preparing the Guest
1. Install Windows on `KVM`
2. Turn off `Windows Defender` and `Windows SmartScreen`
3. Install Python 3.6
4. Set to the IP address described in vm_url.
5. Copy and run `xmlrpc_server.py`
6. Make snapshot

### Setting Web-UI
...

## Usage

* File upload  
Upload the file to be scanned.

* time  
Sets the time to start runing dump tools.
The default is 180 seconds.

* mode
    * hollows_hunter
    * prodump
    * diff(procdump)

## License
tknk_scanner is open-sourced software licensed under the MIT License

## Thanks
@hasherezade - [hollows_hunter](https://github.com/hasherezade/hollows_hunter)  
Sysinternals - https://docs.microsoft.com/en-us/sysinternals/  
yara-python -  https://github.com/VirusTotal/yara-python  
