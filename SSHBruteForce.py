#!/usr/bin/env python3

#import necessary modules
from scapy.all import *
import sys
import os

#Arguments that the file will take
pcap_file = sys.argv[1]
pcap = rdpcap(pcap_file)


#Generate snort rules 
def SSHBF_rule(): 
    if os.path.isfile('/etc/snort/rules/sshbf.rules') == False: 
        f = open('/etc/snort/rules/sshbf.rules', 'x')
        f = open('/etc/snort/rules/sshbf.rules', 'w') 
        f.write('-----------------------------------------------------------------------------\n')
        f.write('There might be a brute force in SSH against your network\n This will give you the alert rules and drop rules against SSH brute force\n')
        f.write('-----------------------------------------------------------------------------\n')

#https://snort-sigs.narkive.com/dpyhPD9r/ssh-brute-force-attack-sig
        f.write('\nBLEEDING-EDGE POTENTIAL SSH SCAN\n')
        f.write('[1] This alert rule tells snort to generate when it detects a TCP SSH protocol dictionary attacks against your network. This rule check packets for TCP protocol from external source to internal source receive any traffic from port 22. The packet header have a SYN flag, which is identified by flags:S, and captured 5 times during a 120 seconds period from the same source address. You can find more information at https://snort-sigs.narkive.com/dpyhPD9r/ssh-brute-force-attack-sig\n\n' + '\nalert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BLEEDING-EDGE Potential SSH Scan"; flags:S; threshold:type threshold, track by_src, count 5, seconds 120; flowbits:set,ssh.brute.attempt;classtype:attempted-dos; sid:2001219; rev:8;)\n' + '\n drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BLEEDING-EDGE Potential SSH Scan"; flags:S; threshold:type threshold, track by_src, count 5, seconds 120; flowbits:set,ssh.brute.attempt;classtype:attempted-dos; sid:2001219; rev:8;)\n\n' +  '----------' + '\n')
#https://seclists.org/snort/2012/q2/121
        f.write('\nSSH BRUTE FORCE LOGIN ATTEMPT\n')
        f.write('[2] This alert rule tells snort to generate when an SSH brute force login attempt that was captured 5 times in 60 seconds. You can find more information at https://seclists.org/snort/2012/q2/121\n\n' + 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BAD-TRAFFIC SSH brute force login attempt"; flow:to_server,established; content:"SSH-"; depth:4;detection_filter:track by_src, count 5, seconds 60;classtype:misc-activity; sid:19559; rev:2;)\n + drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BAD-TRAFFIC SSH brute force login attempt"; flow:to_server,established; content:"SSH-"; depth:4;detection_filter:track by_src, count 5, seconds 60;classtype:misc-activity; sid:19559; rev:2;)\n\n' + '----------\n') 
#https://stackoverflow.com/questions/47742405/using-snort-suricata-i-want-to-generate-an-ssh-alert-for-every-failed-login-to
        f.write('\nSSH BRUTE FORCE ATTEMPT - EXTERNAL TO INTERNAL\n')
        f.write('[3] This alert rule tells if there an possible SSH brute force attempt captured 5 times within 30 second from the external network to the internal network. You can find more information at' + ' https://stackoverflow.com/questions/47742405/using-snort-suricata-i-want-to-generate-an-ssh-alert-for-every-failed-login-to\n\n' + 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH brute forcing!"; flags: S+; threshold: type both, track by_src, count 5, seconds 30; sid:10000001; rev: 1;)\n' + 'drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH brute forcing!"; flags: S+; threshold: type both, track by_src, count 5, seconds 30; sid:10000001; rev: 1;)\n\n' + '----------' + '\n')
#https://wiki.apnictraining.net/_media/sectutorial/05-2_ids_lab_answer.rtf
        f.write('\nSSH BRUTE FORCE ATTACK - THRESHOLD\n')
        f.write('[4] This alert rule tell if SSH brute force attack and log IP trying to connect more than 3 times in 60 seconds. You can find more information at ' + 'https://wiki.apnictraining.net/_media/sectutorial/05-2_ids_lab_answer.rtf\n\n' + 'alert tcp any any -> $HOME_NET 22 (msg:"Potential SSH Brute Force Attack"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; classtype:attempted-dos; sid:4; rev:1; resp:rst_all;)\n' + 'drop tcp any any -> $HOME_NET 22 (msg:"Potential SSH Brute Force Attack"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; classtype:attempted-dos; sid:4; rev:1; resp:rst_all;)\n\n' + '----------' + '\n')

        f.write('\n')
        file_contents_created = f.read()
        print(file_contents_created)
        f.close()   
    else:
        f = open('/etc/snort/rules/sshbf.rules', 'r') #
        file_contents = f.read()
        print(file_contents)
        f.close()


# looking at the packet size - if the bytes in the packet size that the server sends back to the client is less than 5kb it is considered a failed SSH Brute Force attempt and we will generate snort rules (https://resources.infosecinstitute.com/category/certifications-training/network-traffic-analysis-for-incident-response/how-to-use-traffic-analysis-for-wireshark/ssh-protocol-with-wireshark/)
def sshbf_detect():
    sessions = pcap.sessions()
    flag = False
    for session in sessions:
        if not flag:
            for packet in sessions[session]:
                try:
                    payload = bytes(packet["TCP"].payload)
                    if packet['TCP'].sport == 22 and len(payload) < 5000:
                        SSHBF_rule()
                        flag = True
                        break
                except:
                    pass

    if flag == False: 
        print ("there is no brute force")

sshbf_detect()
