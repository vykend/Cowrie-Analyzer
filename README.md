Forked to reflect changes in Cowrie and to add my own stats

# Cowrie-Analyzer
Provides at-a-glance info from the Cowrie honeypot JSON logs 

### Usage
Clone this repo, copy '.py' to the 'cowrie/var/log/' and run with python3.
This can be run from the directory 'cowrie/var/log/' of the Cowrie folder without any configuration or changes.

A sample output can be found below.  Additionally, a simple graph of SSH attempts is created and stored in the file `attack_attempts.png`

### Sample Output

In the subdirectory 'outs/' are stored files for each of the top 30 source IPs with times of attacks - for further analysis

```
SSH attempts:29636
most common source addresses:
5.188.86.172 5201
5.188.62.11 3743
5.182.39.96 3086
5.188.86.174 2945
88.214.26.88 2940
88.214.26.89 2684
88.214.26.93 991
88.214.26.90 853
5.182.39.62 374
222.80.82.243 292
193.112.138.85 279
103.45.115.160 272
5.182.39.64 264
5.182.39.63 258
193.29.13.54 257
5.182.39.97 248
5.182.39.61 200
163.172.223.107 181
141.98.81.150 122
141.98.81.138 117
27.78.14.83 24
116.105.216.179 24
157.230.123.253 22
41.234.66.22 19
92.63.194.104 15
92.63.194.105 15
92.63.194.106 15
92.63.194.107 15
92.63.194.108 15
85.71.8.200 10
most common username attempts:
root 25299
nproc 463
admin 90
oracle 50
test 48
postgres 47
ubuntu 45
hadoop 39
user 33
git 29
pi 25
jenkins 23
ftpuser 17
nginx 14
nagios 13
testuser 13
mysql 12
butter 12
centos 12
teamspeak3 11
debian 11
wildfly 10
nologin 9
minecraft 9
splunk 9
miner 9
library 9
teamspeak 8
zabbix 8
tomcat 7
most common password attempts:
1234 24337
nproc 463
123456 161
password 94
12345 52
123 49
password123 44
admin 36
1 25
user 25
@Dasdd21dDWd1dwaDq 25
qwerty 24
1234567 23
12345678 22
123456789 21
P@ssw0rd 20
 19
123456\r 15
12 15
1234567890 15
raspberryraspberry993311 12
raspberry 12
111111 12
root 10
muiefazan123456 9
test123 9
akduy@akduy47 9
test 8
abc123 7
ubuntu 7
most common username/password combos:
root:1234 24299
nproc:nproc 463
user:user 24
admin:admin 23
admin:password 21
admin: 16
pi:raspberryraspberry993311 12
pi:raspberry 12
root:admin 12
root:password 11
root:123456 7
ubuntu:ubuntu 7
root:root 7
nologin:muiefazan123456 6
root:akduy@akduy47 6
tomcat:tomcat 5
root:!@ 5
git:git 5
postgres:postgres 5
weblogic:weblogic 5
postgres:12 5
postgres:1234 5
ftpuser:ftpuser 5
oracle:oracle 4
mysql:mysql 4
oracle:123456 4
zabbix:zabbix 4
root:P@ssw0rd 4
root:root123 4
root:12345 4
unique source IPs:
1537
unique countries for source IPs:
85
most common countries for source IPs:
China 507
United States 167
France 129
Russia 54
India 53
Germany 50
Brazil 46
Canada 42
South Korea 41
Singapore 33
Vietnam 30
United Kingdom 30
Indonesia 29
Netherlands 27
Italy 23
Taiwan 21
Argentina 17
Colombia 16
Japan 15
Hong Kong 14
Spain 11
Thailand 11
Poland 9
Hungary 9
Romania 7
Mexico 7
Australia 7
Ukraine 7
Pakistan 6
South Africa 6
unique countries for overall attacks:
85
most common countries for overall attacks:
Russia 8312
Ireland 8148
Germany 7554
China 1541
Romania 263
United States 248
Panama 241
Netherlands 217
France 192
India 91
Vietnam 83
Brazil 66
South Korea 59
Canada 59
Singapore 47
United Kingdom 45
Indonesia 37
Taiwan 31
Italy 31
Japan 28
Czechia 25
Argentina 22
Colombia 22
Egypt 21
Hong Kong 21
Spain 17
Poland 17
Thailand 17
Hungary 14
Pakistan 10

```


### Sample of `attack_attempts.png`
![attack_attempts](https://user-images.githubusercontent.com/5506073/32137196-e872196c-bbcf-11e7-8a1c-ccf40e85ccfb.png)



