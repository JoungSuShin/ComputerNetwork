#thread_talk_client.py

import threading
import socket
import argparse


def send_message(s):
        while True:
                send_msgc = input()
                s.sendall(send_msgc.encode())
                
def recv_message(s):
        while True:
                recv_msgc = s.recv(1024)
                print('From',args.i,':',args.p,'' ,recv_msgc.decode())  

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo client -p port -i host")
    parser.add_argument('-p', help="port_number", required=True)
    parser.add_argument('-i', help="host_name", required=True)

    args = parser.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.i, int(args.p)))

    sender = threading.Thread(target = send_message, args=(s,))
    receiver = threading.Thread(target = recv_message, args=(s,))
    sender.start()
    receiver.start()
    
    