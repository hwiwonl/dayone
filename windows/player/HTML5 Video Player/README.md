# CVE-2019-???? (EDB-46279)
* Date : Jan 2019
* Credit : DINO COVOTSOS

## Description
1.) Generate exploit.txt, copy the contents to clipboard
2.) In application, open 'Help' then 'Register'
3.) Paste the contents of exploit.txt under 'KEY CODE'
4.) Click OK - Calc POPS!

Extra Info:
Exact match 996 = For free registration (Fill buffer with ABCD's to get free full registration)
Exact match 997 = For buffer overflow
JMP ESP 0x7cb32d69  shell32.dll

## Vulnerable App

HTML5 Video Player 1.2.5 

## Reference
[Exploit Database](https://www.exploit-db.com/exploits/46279)