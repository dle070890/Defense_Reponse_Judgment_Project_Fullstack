#!/usr/bin/env python3

#import necessary modules
from scapy.all import *
import sys
import os

#Arguments that the file will take
pcap_file = sys.argv[1]
pcap = rdpcap(pcap_file)


#Generate snort rules for SSH brute force
def FTPBF_rule(): 
    if os.path.isfile('/etc/snort/rules/ftpbf.rules') == False: 
        f = open('/etc/snort/rules/ftpbf.rules', 'x')
        f = open('/etc/snort/rules/ftpbf.rules', 'w') 
        f.write('There might be a brute force in FTP against your network. This will give you the alert rules and drop rules against FTP brute force\n')
        f.write('-----------------------------------------------------------------------------\n')

#More information about the rule on https://snort-sigs.narkive.com/k1PO2b22/trouble-in-triggering-the-snort-rule-to-detect-ftp-brute-force-attack
        f.write('\nFTP BRUTE FORCE LOGIN ATTEMPT\n')
        f.write('[1] This alert rule tells snort to generate when an FTP brute force login attempt that was captured 5 times in 60 seconds. You can find more information at https://snort-sigs.narkive.com/k1PO2b22/trouble-in-triggering-the-snort-rule-to-detect-ftp-brute-force-attack\n\n' + 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BAD-TRAFFIC FTP brute force login attempt"; flow:to_server,established; content:"FTP-"; depth:4;detection_filter:track by_src, count 5, seconds 60;classtype:misc-activity; sid:19559; rev:2;)\n + drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BAD-TRAFFIC FTP brute force login attempt"; flow:to_server,established; content:"FTP-"; depth:4;detection_filter:track by_src, count 5, seconds 60;classtype:misc-activity; sid:19559; rev:2;)\n\n' + '----------\n') 
        f.write('\nFTP BRUTE FORCE ATTEMPT - EXTERNAL TO INTERNAL\n')
        f.write('[2] This alert rule tells if there an possible FTP brute force attempt captured 5 times within 30 second from the external network to the internal network. \n\n' + 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"Possible FTP brute forcing!"; flags: S+; threshold: type both, track by_src, count 5, seconds 30; sid:10000001; rev: 1;)\n' + 'drop tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"Possible FTP brute forcing!"; flags: S+; threshold: type both, track by_src, count 5, seconds 30; sid:10000001; rev: 1;)\n\n' + '----------' + '\n')
        f.write('\nFTP BRUTE FORCE ATTACK - THRESHOLD\n')
        f.write('[3] This alert rule tell if FTP brute force attack and log IP trying to connect more than 3 times in 60 seconds. You can find more information at ' + 'https://wiki.apnictraining.net/_media/sectutorial/05-2_ids_lab_answer.rtf\n\n' + 'alert tcp any any -> $HOME_NET 22 (msg:"Potential FTP Brute Force Attack"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; classtype:attempted-dos; sid:4; rev:1; resp:rst_all;)\n' + 'drop tcp any any -> $HOME_NET 21 (msg:"Potential FTP Brute Force Attack"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; classtype:attempted-dos; sid:4; rev:1; resp:rst_all;)\n\n' + '----------' + '\n')

        f.write('\n')
        file_contents_created = f.read()
        print(file_contents_created)
        f.close()   
    else:
        f = open('/etc/snort/rules/ftpbf.rules', 'r') #
        file_contents = f.read()
        print(file_contents)
        f.close()


#looking at the packet size - if the bytes in the packet size that the server sends back to the client is less than 5kb it is considered a failed SSH Brute Force attempt and we will generate snort rules (https://resources.infosecinstitute.com/category/certifications-training/network-traffic-analysis-for-incident-response/how-to-use-traffic-analysis-for-wireshark/ssh-protocol-with-wireshark/)
def ftpbf_detect():
    sessions = pcap.sessions()
    flag = False
    for session in sessions:
        if not flag:
            for packet in sessions[session]:
                try:
                    payload = bytes(packet["TCP"].payload)
                    if packet['TCP'].sport == 21 and len(payload) < 5000:
                        FTPBF_rule()
                        flag = True
                        break
                except:
                    pass

    if flag == False: 
        print ("There is no FTP brute force")

ftpbf_detect()
