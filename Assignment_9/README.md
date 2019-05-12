# 9주차 과제 : Linux에서 IP Packet을 수신해 Ethernet 헤더, IP헤더, 페이로드를 출력하는 프로그램 작성
## 2015040013(김현재), 2015040023(신중수)
  * AF_PACKET을 사용하고 PROTOCOL_TYPE은 ETH_P_ALL을 사용.
  * Ethernet 헤더 파싱 후 Ether_type을 통해 IP 패킷인지 검사 후 IP 패킷일 때만 출력
  * IP헤더는 헤더의 길이를 먼저 구한 뒤 옵션을 제외한 길이에 맞게 파싱
  * While 루프를 통해 여러 번 동작 하도록 작성
  * 프로그램 실행 뒤 www.google.com에 PING을 1번 보낸 결과를 캡쳐해 첨부

## 리눅스에서 ping -c 2 8.8.8.8 명령어를 통해 Google에 PING 한 번 보낸후 결과
![ICMP_PACKET_1](https://user-images.githubusercontent.com/48250660/57583200-12148180-7509-11e9-9bc0-3c340242cd14.png)

![ICMP_PACKET_2](https://user-images.githubusercontent.com/48250660/57583212-25bfe800-7509-11e9-9683-6173bf442baf.png)

