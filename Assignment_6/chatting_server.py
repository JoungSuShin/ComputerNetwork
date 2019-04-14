

import socket
import threading
import argparse


def send_message(conn):
    while True:
        send_msgs = input()
        conn.sendall(send_msgs.encode())

def recv_message(conn):
    while True:
        recv_msgs = conn.recv(1024)
        print('From',addr[0],':', addr[1],'', recv_msgs.decode())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Thread server -p port")
    parser.add_argument('-p', help = "port_number", required = True)

    args = parser.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', int(args.p)))
    server.listen(1)

    conn, addr = server.accept()
    print('Connected : ',addr[0], ' : ', addr[1])
    sender = threading.Thread(target = send_message, args=(conn,))
    receiver = threading.Thread(target = recv_message, args = (conn,))
    sender.start()
    receiver.start()


    server.close()