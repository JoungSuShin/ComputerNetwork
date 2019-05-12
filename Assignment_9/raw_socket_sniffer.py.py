import os
import socket
import argparse
import struct

ETH_P_ALL = 0x0003
ETH_H_SIZE = 14
cnt = 1


def make_ethernet_header(raw_data):
   ether = struct.unpack('!6B6BH', raw_data)
   return {'[dst]' : '%02x:%02x:%02x:%02x:%02x:%02x' % ether[:6],
   '[src]' : '%02x:%02x:%02x:%02x:%02x:%02x' % ether[6:12],
   '[ether_type]' : ether[12]}

def make_1Byte_IP(raw_data):
   ver_len_ip = struct.unpack('!B', raw_data) # 1Byte를 먼저 읽는다.
   version = ver_len_ip[0] >> 4 # version을 구하기위해 오른쪽으로 4bit shift
   header_length = ver_len_ip[0] & 0x0f # 헤더길이를 구하기 위해 0x0f와 and 연산 (0100 0101 & 0000 1111 = 0000 0101)
   print('[version] : %d' % version)
   print('[header_length] : %d' % header_length)
   return header_length
def make_ip_header(raw_data):
   
   ip = struct.unpack('!BHHHBBH4B4B', raw_data) # 
   flag = ip[3] >> 13 # 3bit
   offset = ip[3] & 0x1fff # 16bit
   return {
   '[tos]' : ip[0], 
   '[total_length]' : ip[1],
   '[id]' : ip[2], 
   '[flag]' : flag, 
   '[offset]' : offset,  
   '[ttl]' : ip[4], 
   '[protocol]' : ip[5], 
   '[checksum]' : ip[6], 
   '[src]' : '%d.%d.%d.%d' % ip[7:11], 
   '[des]' : '%d.%d.%d.%d' % ip[11:15]}

def dumpcode(buf):
   print("\nRaw Data")
   print("%7s"% "offset ", end='')

   for i in range(0, 16):
      print("%02x " % i, end='')

      if not (i%16-7):
         print("- ", end='')

   print("")

   for i in range(0, len(buf)):
      if not i%16:
         print("0x%04x" % i, end= ' ')

      print("%02x" % buf[i], end= ' ')

      if not (i % 16 - 7):
         print("- ", end='')

      if not (i % 16 - 15):
         print(" ")

   print("")   

def sniffing(nic):
   global cnt

   if os.name == 'nt':
      address_family = socket.AF_INET
      protocol_type = socket.IPPROTO_IP
   else:
      address_family = socket.AF_PACKET
      protocol_type = socket.ntohs(ETH_P_ALL)
   
   with socket.socket(address_family, socket.SOCK_RAW, protocol_type) as sniffe_sock:
      sniffe_sock.bind((nic, 0))

      if os.name == 'nt':
         sniffe_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
         sniffe_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

      data, _ = sniffe_sock.recvfrom(65535)
      if data[12] == 8 and data[13] == 0 : # Ipv4 (0x0800) 일때만 실행
         print("\n[%d] IP_PACKET------------------------------------------\n-" % cnt)
         ethernet_header = make_ethernet_header(data[:ETH_H_SIZE]) #Ethernet 헤더 파싱 
         print('Ethernet Header')
         for item in ethernet_header.items():
            print('{0} : {1}'.format(item[0], item[1]))
         print('\nIp Header')
         ver_len_IP = make_1Byte_IP(data[ETH_H_SIZE:ETH_H_SIZE + 1]) #IP 헤더 1바이트 먼저 파싱
         IP_H_SIZE = ver_len_IP * 4 # 읽어들인 헤더길이 값에 4를 곱하여 헤더사이즈를 구함
         ip_header = make_ip_header(data[ETH_H_SIZE+1:ETH_H_SIZE + IP_H_SIZE]) # 그 다음부터 옵션필드를 제외한 나머지부분 파싱
         for item in ip_header.items():
            print('{0} : {1}'.format(item[0], item[1]))

         dumpcode(data) # 패킷정보 출력
         print("--------------------------------------------------------")
         cnt += 1
      else:
         print("---------It's not IPV4------------")
         dumpcode(data) # IPv4가 아닐시 패킷정보만 출력
         
         

      if os.name == 'nt':
         sniffe_sock.ioct1(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
   parser = argparse.ArgumentParser(description = 'This is a simple packet sniffer')
   parser.add_argument('-i', type = str, required = True, metavar = 'NIC name', help = 'NIC name')
   args = parser.parse_args()
   while(True) :
      sniffing(args.i)
