#!/bin/bash/

task1:
1)sudo useradd noor
2)ubuntu@ubuntu:~/lab2-noor5530$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
usbmux:x:103:46:usbmux daemon,,,:/home/usbmux:/bin/false
dnsmasq:x:104:65534:dnsmasq,,,:/var/lib/misc:/bin/false
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
kernoops:x:106:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
rtkit:x:107:114:RealtimeKit,,,:/proc:/bin/false
saned:x:108:115::/home/saned:/bin/false
whoopsie:x:109:116::/nonexistent:/bin/false
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
avahi:x:111:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
lightdm:x:112:118:Light Display Manager:/var/lib/lightdm:/bin/false
colord:x:113:121:colord colour management daemon,,,:/var/lib/colord:/bin/false
hplip:x:114:7:HPLIP system user,,,:/var/run/hplip:/bin/false
pulse:x:115:122:PulseAudio daemon,,,:/var/run/pulse:/bin/false
ubuntu:x:999:999:Live session user,,,:/home/ubuntu:/bin/bash
noor:x:1000:1000::/home/noor:
3)ubuntu@ubuntu:~/lab2-noor5530$ sudo passwd noor
Enter new UNIX password: 
Retype new UNIX password: 
passwd: password updated successfully
4)ubuntu@ubuntu:~/lab2-noor5530$ sudo cat /etc/shadow
root:*:17967:0:99999:7:::
daemon:*:16848:0:99999:7:::
bin:*:16848:0:99999:7:::
sys:*:16848:0:99999:7:::
sync:*:16848:0:99999:7:::
games:*:16848:0:99999:7:::
man:*:16848:0:99999:7:::
lp:*:16848:0:99999:7:::
mail:*:16848:0:99999:7:::
news:*:16848:0:99999:7:::
uucp:*:16848:0:99999:7:::
proxy:*:16848:0:99999:7:::
www-data:*:16848:0:99999:7:::
backup:*:16848:0:99999:7:::
list:*:16848:0:99999:7:::
irc:*:16848:0:99999:7:::
gnats:*:16848:0:99999:7:::
nobody:*:16848:0:99999:7:::
libuuid:!:16848:0:99999:7:::
syslog:*:16848:0:99999:7:::
messagebus:*:16848:0:99999:7:::
usbmux:*:16848:0:99999:7:::
dnsmasq:*:16848:0:99999:7:::
avahi-autoipd:*:16848:0:99999:7:::
kernoops:*:16848:0:99999:7:::
rtkit:*:16848:0:99999:7:::
saned:*:16848:0:99999:7:::
whoopsie:*:16848:0:99999:7:::
speech-dispatcher:!:16848:0:99999:7:::
avahi:*:16848:0:99999:7:::
lightdm:*:16848:0:99999:7:::
colord:*:16848:0:99999:7:::
hplip:*:16848:0:99999:7:::
pulse:*:16848:0:99999:7:::
ubuntu:U6aMy0wojraho:17967:0:99999:7:::
noor:$6$QSVjis6E$H9/IU4m5WN9qvdu5s7Z3xnHJLvDUoKTk1zsOPr7cUTWPdgKXJYVz4MIgYM1ZbdsqohYm97r8WRB5kivQsaZ1Z.:17967:0:99999:7:::
5)ubuntu@ubuntu:~/lab2-noor5530$ su noor
Password: 
6)noor@ubuntu:/home/ubuntu/lab2-noor5530$ usermod -n
usermod: invalid option -- 'n'
Usage: usermod [options] LOGIN
7)noor@ubuntu:/home/ubuntu/lab2-noor5530$ cat /etc/default/useradd
# Default values for useradd(8)
#
# The SHELL variable specifies the default login shell on your
# system.
# Similar to DHSELL in adduser. However, we use "sh" here because
# useradd is a low level utility and should be as general
# as possible
SHELL=/bin/sh
#
# The default group for users
# 100=users on Debian systems
# Same as USERS_GID in adduser
# This argument is used when the -n flag is specified.
# The default behavior (when -n and -g are not specified) is to create a
# primary user group with the same name as the user being added to the
# system.
# GROUP=100
#
# The default home directory. Same as DHOME for adduser
# HOME=/home
#
# The number of days after a password expires until the account 
# is permanently disabled
# INACTIVE=-1
#
# The default expire date
# EXPIRE=
#
# The SKEL variable specifies the directory containing "skeletal" user
# files; in other words, files such as a sample .profile that will be
# copied to the new user's home directory when it is created.
# SKEL=/etc/skel
#
# Defines whether the mail spool should be created while
# creating the account
# CREATE_MAIL_SPOOL=yes
8)sudo passwd root
 su noor
9)su noor
Password: 
noor@ubuntu:/home/ubuntu/lab2-noor5530$ sudo passwd noor
[sudo] password for noor: 
Sorry, try again.
10)chfn noor
Password: 
Changing the user information for noor
Enter the new value, or press ENTER for the default
	Full Name: 
	Room Number []:  
	Work Phone []: 
	Home Phone []: 
noor@ubuntu:/home/ubuntu/lab2-noor5530$ su root
Password: 
su: Authentication failure
11)noor@ubuntu:/home/ubuntu/lab2-noor5530$ sudo cat /etc/shadow
[sudo] password for noor: 
noor is not in the sudoers file.  This incident will be reported.


task2:
a) sudo usermod -L noor
b)sudo usermod -U noor
c)userdel noor
d)noor@ubuntu:/home/ubuntu/lab2-noor5530$ ls noor
ls: cannot access noor: No such file or directory
e)sudo cat/etc/group
f) sudo chfn -f noor un-nisa
g) sudo chfn -f noor un-nisa
h)userdel -r un-nisa
i) sudo cat etc/passwd
j)userdel -r un-nisa



task3:
a)adduser hina
b)adduer noor
 #ther user already exist
d) sudo cat /etc/login.defs
e)adduser noor


task4:
a)sudo addgroup sales
  cat /etc/group
b)sudo groupmod -n marketing sales
c)sudo delgroup marketing
d)sudo useradd user1
 cat /etc/group
e)sudo delgroup user1
f)sudo addgroup technology
  cat /etc/group
g) sudo useradd hadeed
   id hadeed
h)sudo usermod -G technology hadeed
i)sudo delgroup technology
j)sudo useradd Maaz
k)sudo usermod -g technology Maaz
l)sudo delgroup technology
m)sudo addgroup cs
  sudo addgroup mkt
  sudo addgroup sales
n)sudo usermod -G cs xyz
  sudo usermod -G mkt xyz
  sudo useradd xyz


task5:
a) sudo adduser Tariq
   sudo adduser Khan
   sudo adduser Jamil
b)mkdir ~/dir1
  toch ~/dir1/file1
c)su Tariq
  ls Khan
d)su Khan
  mkdir /tmp/dir1
  touch /tmp/dir1/file1
e)su Tariq
  ls dir
 f)usermod -g sales Khan
   usermod -G mkt Khan
   usermod -g mkt Jmail
g)chmod -rw /tmp/dir1/file1
h)su Tariq 
  ls /tmp/dir1/file1
i)chown root sales
j)gedit /tmp/dir1/file1
k)gedit tmp/dir1/file1




task6:
a)chmod -r-rw----- test1
b
1)drwxr----- 2
2)chmod u=rwx course
  ls-ld course
3)chmod 700 - course
  ls-ld course
4)chmod ugo-rw sample
   ls-ld sample
5)chmod a-rw sample
   ls-ld sample
6)chmod a+x sample
  ls-ld sample
7)chmod g=u sample
  ls-ld sample
8)chmod go= sample
  ls-ld sample