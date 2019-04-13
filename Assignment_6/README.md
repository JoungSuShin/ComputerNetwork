# 6주차 과제 : Threading 모듈을 사용해 서버와 클라이언트가 대화를 주고 받을 수 있는 프로그램 작성

### 2015040013(김현재), 2015040023(신중수)
* 서버는 클라이언트가 전송한 문자열을 출력, input()으로 사용자 입력을 받아서 클라이언트에 전달
* 클라이언트는 서버가 전송한 문자열 출력, input()으로 사용자 입력을 받아서 서버에 전달
* 서버는 1개의 클라이언트를 처리

구분|Blocking|Non-blocking 
:----|:----|:----
Synchronous : 동기|Read/Write | Read/Write(Polling)
Asynchronous : 비동기 |I/O Multiplexing(select/Poll)| Asynchronous I/O


> 서버와 클라이언트가 지속적으로 메시지를 주고 받으려면?
>> 새로운 요청처리 스레드 + 사용자 입력 스레드 + 클라이언트 입력 수신 스레드 
>>
>> ---------->> 서버와 클라이언트에 각각 입력, 수신 스레드 생성하여 처리

## Result

![chatting](https://user-images.githubusercontent.com/48250660/56074962-d5644600-5df5-11e9-8358-d702b9b08a7f.png)




