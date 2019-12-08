# UNACEV2.dll 임의경로 압축해제 취약점

## Information
- CVE : 2018-20250
- 해당 소프트웨어 : WinRAR, BANDIZIP, ALZIP 등 ACE 파일 압축 해제를 지원하는 프로그램
- 해당 버전 : WINRAR <=5.61, BANDIZIP <6.21 등
- 취약점 유형 : 디렉토리 경로 조작

## Background
### unacev2.dll
Winrar을 포함한 압축 및 압축 해제 프로그램에서 ACE포맷의 파일을 파싱하는데 공통적으로  unacev2.dll을 사용한다. 이 dll은 2006년에 컴파일된 오래된 dll으로서, 보호메커니즘조차 없이 만들어진 dll임을 알 수 있다. 이 취약점을 이해하기 위해, Winrar에서 해당 dll을 호출하는 방식을 알아야 한다.  바이너리를 분석해보면, 아래 함수가 순서대로 호출되어야 함을 알 수 있다. CheckPoint에서 취약점을 발견하고, 이를 익스플로잇하기까지의 상세 과정을 공개하였는데, 이하 내용은 이를 번역 및 재구성하여 작성한 글임을 우선 밝힌다.

* 먼저, ACEInitDll이라는 이름을 가진 초기화 함수를 보면, 아래와 같이 `struct_1` 이라는 알 수 없는 구조체에 대한 포인터를 받는다.
```c++
INT __stdcall ACEInitDll(unknown_struct_1 *struct_1);
```
* 다음으로, ACEExtract라는 이름의 압축해제 함수가 호출되어야 한다.  이는 두 개의 인자를 받는데, 하나는 압축 해제할 ace 파일의 이름인 `string`에 대한 포인터이고, 두 번째 인자는 알려지지 않은 구조체이다.  
```c++
INT __stdcall ACEExtract(LPSTR ArchiveName, unknown_struct_2 *struct_2);
```
[FarManager](https://github.com/FarGroup/FarManager)라는 Github 프로젝트를 통해  두 함수에서 알려지지 않은 구조체를 이해해볼 수 있다. 여기서 제공하는 헤더  파일을 IDA에 로드하면, 아래와 같이 구조체 정보를 복구할 수 있다. 
```c++
INT __stdcall ACEInitDll(pACEInitDllStruc DllData);
INT __stdcall ACEExtract(LPSTR ArchiveName, pACEExtractStruc Extract);
```
### ACE 포맷 이해
ACE 아카이브 생성 자체는 특허로 보호되고 있기에, WinACE로만 파일을 생성할 수 있다. 또한, 이는 2007년 11월이 최종 버전이다. (ACE에서 파일을 추출하는 것은 특허 범위에 포함되지 않는다.)  ACE 파일의 구조를 파악하기 위해, WinACE를 이용하여 ace 파일을 생성한 후,  헤더정보를 확인해보면 아래 그림과 같다.

[acefile 프로젝트](https://pypi.org/project/%3Ccode%3Eacefile%3C/code%3E%20/)에서 제공하는 acefile.py를 이용하여 헤더 정보를 분석하면, 아래 그림과 같은 정보를 알 수 있다. 

중요한 정보들은 아래와 같다.
* hdr_crc(분홍색)
2개의 헤더에 각각 CRC필드가 있다. 이 CRC가 데이터와 일치하지 않으면 추출이 중단된다. 이를 고려하지 않고 퍼징하면 제대로 된 경로를 추적할 수 없게 된다. 
* 파일 이름(녹색) 
파일의 상대 경로를 나타낸다. 
* advert (노란색)
WinACE가 등록되지 않은 버전을 사용하여 생성된 경우 이 필드는 자동으로 생성된다.
* 파일 내용 
 - origsize : 내용의 크기를 나타낸다.
 - hdr_size : 헤더 크기이다. 

이 중, filename 필드에서 상대 경로를 포함하므로, Path Traversal에 취약할 가능성이 있다. 이를 중심으로 퍼저를 제작하여 발견한 취약점은 아래와 같다. 
(퍼저 그림)
위 그림을 보면, 의도되지 않은 경로에 의도하지 않은 파일을 압축 해제함을 알 수 있다. 그러나, 이를 WinRAR에서 제대로 trigger하여 임의의 경로에 파일을 쓰기 위해서는 유효성 검증 절차를 통과해주어야 한다. 

(유효성 검사 그림)

그 의사 코드는 위와 같고, 요약하면 아래와 같다.
1. 첫 번째 문자는 "\"이나 "/"이 아닐 것
2. 파일이름은 "../"이나 "..\"으로 시작하지 않을 것
3. “\..\”, “\../”, “/../”, “/..\”과 같은 가젯도 존재하지 않을 것

unac
## Root Cause

## Patch
본 취약점을 해결하기 위해서는 UNACEV2.dll의 코드를 수정해야 한다. 그러나, 압축프로그램 벤더사에 해당 dll의 소스가 부재하고, 해당 dll의 추가 패치가 어렵다고 판단하여 WinRAR, BANDIZIP 등의 상위 버전에서는 해당 포맷의 압축 해제를 미지원하는 방식으로 패치하였다. 이는 기존에 ACE포맷의 압축이 잘 쓰이지 않았던 것도 함꼐 고려되었을 것으로 판단된다.

 
## PoC
```python

```

## How to run exploit?
취약한 버전의 apache struts가 운용된 상태에서, target IP 설정 후 PoC 실행. 
## Reference
- [CheckPoint Research: Extracting a 19 Year Old Code Execution from WinRAR ](https://research.checkpoint.com/extracting-code-execution-from-winrar/)
- [NIST NVD: CVE-2018-20250]()
- [tenable : WinRAR Absolute Path Traversal Vulnerability Leads to Remote Code Execution (CVE-2018-20250)]()
