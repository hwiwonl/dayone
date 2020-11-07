# PHP7 PHP-FPM UnderFlow RCE (CVE-2019-11043)
* Date : Oct 2019
* Credit : [Omar Ganiev](https://twitter.com/ahack_ru)
* CVSS : [9.8](https://nvd.nist.gov/vuln/detail/CVE-2019-11043)
* Affected Versions : NGINX + PHP version < 7.3.11 or < 7.2.24

## Root Cause Analysis
해당 취약점은 NGINX와 PHP7을 함께 구동하는 환경에서 트리거 할 수 있다. PHP-FPM(PHP FastCGI Process Manager)은 웹서버와 PHP를 연결해주며, PHP를 FastCGI 모드로 동작하도록 해준다. PHP-FPM을 지원하는 NGINX에서는 PHP-FPM의 원격코드실행 취약점이 발생한다. 취약점이 발생하는 근본적인 원인은 아래와 같은 정규식을 우회할 수 있다는 것이다.

###NGINX의 URL 분리
```
fastcgi_split_path_info ^(.+?\.php)(/.*)$;
```

path_info 변수에 값을 넣을 때, 위와 같은 정규표현식을 사용한다. 정규표현식에서 '.'에 해당하는 문자는 '\n'을 포함하지 않기 때문에 php-cgi의 PATH_INFO 변수로 들어가는 값에 '/x.php/a%0ab' 이런식으로 '\n' 문자를 넣어주면 정규표현식을 우회하여 PATH_INFO 환경변수에 아무값도 들어가지 않도록 만들 수 있다. 이는 PATH_INFO의 길이가 0으로 간주하도록 만든다.

###sapi/fpm/fpm/fpm_main.c 취약한 소스
```C
if (apache_was_here) {
                                /* recall that PATH_INFO won't exist */
                                path_info = script_path_translated + ptlen;
                                tflag = (slen != 0 && (!orig_path_info || strcmp(orig_path_info, path_info) != 0));
                            } else {
                                path_info = (env_path_info && pilen > slen) ? env_path_info + pilen - slen : NULL;
                                tflag = path_info && (orig_path_info != path_info);
                            }
```
위 코드에서 path_info에 pilen 값이 0으로 들어가면 path_info 포인터에 이상한 값이 들어가게 된다. 또한 PATH_INFO 값이 비어있는 것으로 간주하여 정상경로로 판단하고, 아래와 같은 FCGI_PUTENV가 호출되는 로직으로 들어간다.

###FCGI_PUTENV 함수의 호출
```C
if (orig_path_info) {
                                    char old;

                                    FCGI_PUTENV(request, "ORIG_PATH_INFO", orig_path_info);
                                    old = path_info[0];
                                    path_info[0] = 0;
                                    if (!orig_script_name ||
                                        strcmp(orig_script_name, env_path_info) != 0) {
                                        if (orig_script_name) {
                                            FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
                                        }
                                        SG(request_info).request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_path_info);
                                    } else {
                                        SG(request_info).request_uri = orig_script_name;
                                    }
                                    path_info[0] = old;
```

여기서 공격자가 URL과 쿼리 문자열 길이를 정확하게 맞추면, PATH_INFO를 _fcgi_data_seg의 첫번째 바이트(*pos)로 지정할 수 있고, path_info[0] = 0를 하는 과정에서 pos에 0이 들어가면, Underflow가 발생한다. 그러면 PATH_INFO의 길이를 조절해서 원하는 위치에 원하는 데이터가 쓰여지도록 만들 수 있다.

## PoC Testing

### Docker 이미지를 활용한 PoC
```
$ git clone https://github.com/neex/phuip-fpizdam
$ cd reproducer

# docker build & run
$ docker build -t test1142 . ; docker run --rm -ti -p 9556:80 test1142
```
```bash
$ cd phuip-fpizdam
$ rm -rf go.mod go.sum
$ go build
./phuip-fpizdam
```
```
./phuip-fpizdam http://localhost:9556/script.php
```

## Reference
- [Hahwul](https://www.hahwul.com/2019/10/28/php7-underflow-rce-vulnerabliity/)
- [Emil Lerner](https://github.com/neex/phuip-fpizdam/blob/master/ZeroNights2019.pdf)
- [PHP bugs](https://bugs.php.net/bug.php?id=78599)