#!/bin/bash
#Script Variables

MYIP=$(wget -qO- icanhazip.com);
server_ip=$(curl -s https://api.ipify.org)
timedatectl set-timezone Asia/Riyadh

apt-get update
apt-get upgrade -y
apt-get install lolcat -y 
gem install lolcat
sudo apt install python -y
clear
 
[[ ! "$(command -v curl)" ]] && apt install curl -y -qq
[[ ! "$(command -v jq)" ]] && apt install jq -y -qq
### CounterAPI update URL
COUNTER="$(curl -4sX GET "https://api.countapi.xyz/hit/BonvScripts/DebianVPS-Installer" | jq -r '.value')"

IPADDR="$(curl -4skL http://ipinfo.io/ip)"

GLOBAL_API_KEY="1d0e138b7b9c1368f6cc1b5f8fef94e3c25a8"
CLOUDFLARE_EMAIL="d.eskalarte@gmail.com"
DOMAIN_NAME_TLD="api-mediatekold.online"
DOMAIN_ZONE_ID="0c7a82da29c948deb20007b850811146"
### DNS hostname / Payload here
## Setting variable

####
## Creating file dump for DNS Records 
TMP_FILE='/tmp/abonv.txt'
curl -sX GET "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records?type=A&count=1000&per_page=1000" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "Content-Type: application/json" | python -m json.tool > "$TMP_FILE"

## Getting Existed DNS Record by Locating its IP Address "content" value
CHECK_IP_RECORD="$(cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.content' | awk '!a[$0]++')"

cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.name' | awk '!a[$0]++' | head -n1 > /tmp/abonv_existed_hostname

cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.id' | awk '!a[$0]++' | head -n1 > /tmp/abonv_existed_dns_id

function ExistedRecord(){
 MYDNS="$(cat /tmp/abonv_existed_hostname)"
 MYDNS_ID="$(cat /tmp/abonv_existed_dns_id)"
}


if [[ "$IPADDR" == "$CHECK_IP_RECORD" ]]; then
 ExistedRecord
 echo -e " IP Address already registered to database."
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
 echo -e ""
 else

PAYLOAD="mtk"
echo -e "Your IP Address:\033[0;35m $IPADDR\033[0m"
read -p "Enter desired DNS: "  servername
read -p "Enter desired servername: "  servernames
### Creating a DNS Record
function CreateRecord(){
TMP_FILE2='/tmp/abonv2.txt'
TMP_FILE3='/tmp/abonv3.txt'
curl -sX POST "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "Content-Type: application/json" --data "{\"type\":\"A\",\"name\":\"$servername.$PAYLOAD\",\"content\":\"$IPADDR\",\"ttl\":86400,\"proxied\":false}" | python -m json.tool > "$TMP_FILE2"

cat < "$TMP_FILE2" | jq '.result' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' > /tmp/abonv22.txt
rm -f "$TMP_FILE2"
mv /tmp/abonv22.txt "$TMP_FILE2"

MYDNS="$(cat < "$TMP_FILE2" | jq -r '.name')"
MYDNS_ID="$(cat < "$TMP_FILE2" | jq -r '.id')"
curl -sX POST "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "Content-Type: application/json" --data "{\"type\":\"NS\",\"name\":\"$servernames.$PAYLOAD\",\"content\":\"$MYDNS\",\"ttl\":1,\"proxied\":false}" | python -m json.tool > "$TMP_FILE3"

cat < "$TMP_FILE3" | jq '.result' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' > /tmp/abonv33.txt
rm -f "$TMP_FILE3"
mv /tmp/abonv33.txt "$TMP_FILE3"

MYNS="$(cat < "$TMP_FILE3" | jq -r '.name')"
MYNS_ID="$(cat < "$TMP_FILE3" | jq -r '.id')"
echo "$MYNS" > nameserver.txt
}

 CreateRecord
 echo -e " Registering your IP Address.."
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
 echo -e ""
fi

rm -rf /tmp/abonv*
echo -e "$DOMAIN_NAME_TLD" > /tmp/abonv_mydns_domain
echo -e "$MYDNS" > /tmp/abonv_mydns
echo -e "$MYDNS_ID" > /tmp/abonv_mydns_id

function ip_address(){
  local IP="$( ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$(curl -4s ipv4.icanhazip.com)"
  [ -z "${IP}" ] && IP="$(curl -4s ipinfo.io/ip)"
  [ ! -z "${IP}" ] && echo "${IP}" || echo '0.0.0.0'
}

function DEX-MSG(){
 echo -e "\033[1;31m═══════════════════════════════════════════════════\033[0m"
echo '                                                              
      ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗ 
      ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗
      ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝
      ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗
      ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║
      ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝  
 '
echo -e "\033[1;31m═══════════════════════════════════════════════════\033[0m"
}

system_package (){
sudo timedatectl set-timezone Asia/Manila
timedatectl
apt-get update -y
sudo apt install screen
ufw disable
apt update
apt install -y gnupg openssl
apt install -y iptables socat
apt install -y netcat httpie php neofetch vnstat
apt install -y pwgen python php jq curl
apt install -y dos2unix nano unzip jq virt-what net-tools default-mysql-client
apt install -y build-essential
sed -i 's/Listen 80/Listen 81/g' /etc/apache2/ports.conf
service apache2 restart
}

modify_badvpn(){

clear
echo 'modifying badvpn'
{
wget -O /usr/bin/badvpn-udpgw "https://apk.admin-boyes.com/setup/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
ps x | grep 'udpvpn' | grep -v 'grep' || screen -dmS udpvpn /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 10000 --max-connections-for-client 10 --client-socket-sndbuf 10000
}

install_firewall_kvm () {
clear
echo "Installing iptables."
echo "net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.eth0.rp_filter=0" >> /etc/sysctl.conf
sysctl -p
{
iptables -F
iptables-save > /etc/iptables_rules.v4
ip6tables-save > /etc/iptables_rules.v6
}

install_rclocal(){
{
echo "[Unit]
Description=tknetwork service
Documentation=http://teamkidlat.com

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/rc.local
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/tknetwork.service
echo '#!/bin/sh -e
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
sysctl -p
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
exit 0' >> /etc/rc.local
sudo chmod +x /etc/rc.local
systemctl daemon-reload
sudo systemctl enable tknetwork
sudo systemctl start tknetwork.service  
}


install_dropbear (){

apt-get -y install dropbear
rm -rf /etc/default/dropbear

cat > /etc/default/dropbear << MyDropbear
NO_START=0
DROPBEAR_PORT=442
DROPBEAR_EXTRA_ARGS="-p 551"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells

service dropbear restart
service ssh restart

#install_banner
echo "Adding banner."

cat > /etc/banner << MyBanner
<br>
==========================
<br><font color=red size=7><b>WARNING</b></font>
<br>
==========================
<br>
<i><font color='green'>- NO SPAMMING !!!</br></font></i>
<br><i><font color='green'>- NO DDOS !!!</br></font></i>
<br><i><font color='green'>- NO HACKING !!!</br></font></i>
<br><i><font color='green'>- NO CARDING !!!</br></font></i>
<br><i><font color='green'>- NO TORRENT !!!</i></br></font></i>
<br>
==========================
<br><font color=yellow size=7><b>POWERED BY: Mediatek</b></font>
<br>
MyBanner

}

install_stunnel () {
apt-get install stunnel4 -y > /dev/null 2>&1
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/bin/cat <<"EOM" > /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyN+jQb8vvS1jwbQSXAP9H0alRxuXuijhIp3u1gePGBsGLGg8
CWQrdhbB40W7Ov2xzg4KyiRwLgcfnOP2tHvtsN7BzC8DWrqqZsNyENDyIs3sX5oc
+JGLQZJiv2QSAP3N/4/UAAswUnGRW1TzQFXISSVeiScBsB96LoVLiPdA1e4Hhjkb
vggLOHHTcXqc1BBzIt9eg672O+yiILsOFuYPGh3TBwVZ0DvKYZocEsJ/RExOuAID
x0+THlpyO3PZhIo3EN5BVCmBcsUboByH9/Lsh+15tJqpvM8uiB9pjxlWUiRNiHjm
J5+pOWX4FpGlgrJUYSSsUUddXmPVWAj1BeQ2GwIDAQABAoIBAH7ISC5zERqBz3iu
wve4vMZEvISI8dbZfl9u9xO3aaV5SQg2Mc5rntLFwlJD7Mxq2xKG4mB7ZyJl9Jn9
d/SqU3dS4VaSRbe6IVsC+LeMaYd2GT6t8qMgmZglYJYT/xkJGD+488GjTjh63Zeb
onx0qBkisOw35mTXOTKrhuVHyXA70dD1an0fXi6tiNkIT4AVwLgqJuFxE0seePlN
Y35jZF4JvX8hOvkSshkzxNWSIs2LOOCJL7dH90FYvUYA/kvW+64O7pouA/p/VkYD
rO0fYgJmureiUZfwEVJKfnBgdhIbStA3lRxDzDmxr1BBVFaraSZ+12/jQVEXOaRb
ErovK6ECgYEA5nV12egMRn3l3MItWmcURIDtTU8cy3WreP2zTzx9RZDs3Rw2HEbR
0jyLzJOHfyFdyGrZtbUAa/LoOKT2YvPKQ2P4k4ZFbYcnl7cgAL28CrpZgNZXoEaL
sMf6Qp6PG+VUSFoFcOi/GM2c4ZypVOR5MwGbfpJ4fusekxQiTijWs4cCgYEA3yLK
Kt8bXHgg7B92mTFEKsiYrgk5SgPcYQ/HxYOMS3hrI8J3JWkMOWCCAbS1nSPPd0BY
jXGL/LSRmWA8bX/objwq8Q8YDTuuDCIPsh/SoFZsdHWc0ZlOv1BsWGijJGa21n64
Ja5r3LWSH6YLCy2PmoQzBDaCtmr/rZWXPaS4tc0CgYEAre9jJjab5SwqK6amQj/g
LR+9eobGLc0+wM+B4MC/r5yFGRCsykStIeaugJWsQ0g0lwoGDL1ydwbbO71NdDuZ
oak3OGizx8mlGT2OOuD4poQk/zdG5WG5FpCoElXHnv9D0GOZDbGsYRT2XdU2fCsA
Sn3hFPOJXAkqh0k/5wutl8sCgYEA2aXAluK6eI7AZjEmaLTSbfzuWEus8tIjQxW2
YaU30mGp9952gyoc/1ZwWSOgRp+ofQRpm8XWqu6iWn2xU4mA+Q19QVbcugOteC49
Kxy5QSYrcclK5nNoiVnz5KRkBVyfGUfPbQneMhF1b6NxgDy3pxst+/0DsNVbgUC5
niou9T0CgYEAkTXYooaf7JTAMlu/wLunkT0ZWKL/bU4ZgOFVFnF2gdfWJnHTMSu5
PtxyjisZJNbON6xW0pIjcTuUQCIpL0LoZ7qd5zi5QqISb+eKzK8ENMxgnV7MEx78
lufFKJYrjhC8j9pwY5pAR5uw2HKMS34IqLXct6NypoEYsJ48YDfA0Qw=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEATCCAumgAwIBAgIJAPDuiksIWVs2MA0GCSqGSIb3DQEBCwUAMIGWMQswCQYD
VQQGEwJQSDESMBAGA1UECAwJU1RST05HVlBOMRIwEAYDVQQHDAlTVFJPTkdWUE4x
EjAQBgNVBAoMCVNUUk9OR1ZQTjESMBAGA1UECwwJU1RST05HVlBOMRIwEAYDVQQD
DAlTVFJPTkdWUE4xIzAhBgkqhkiG9w0BCQEWFHN0cm9uZy12cG5AZ21haWwuY29t
MB4XDTE4MDcwMzA1MTM0MVoXDTIxMDcwMjA1MTM0MVowgZYxCzAJBgNVBAYTAlBI
MRIwEAYDVQQIDAlTVFJPTkdWUE4xEjAQBgNVBAcMCVNUUk9OR1ZQTjESMBAGA1UE
CgwJU1RST05HVlBOMRIwEAYDVQQLDAlTVFJPTkdWUE4xEjAQBgNVBAMMCVNUUk9O
R1ZQTjEjMCEGCSqGSIb3DQEJARYUc3Ryb25nLXZwbkBnbWFpbC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDI36NBvy+9LWPBtBJcA/0fRqVHG5e6
KOEine7WB48YGwYsaDwJZCt2FsHjRbs6/bHODgrKJHAuBx+c4/a0e+2w3sHMLwNa
uqpmw3IQ0PIizexfmhz4kYtBkmK/ZBIA/c3/j9QACzBScZFbVPNAVchJJV6JJwGw
H3ouhUuI90DV7geGORu+CAs4cdNxepzUEHMi316DrvY77KIguw4W5g8aHdMHBVnQ
O8phmhwSwn9ETE64AgPHT5MeWnI7c9mEijcQ3kFUKYFyxRugHIf38uyH7Xm0mqm8
zy6IH2mPGVZSJE2IeOYnn6k5ZfgWkaWCslRhJKxRR11eY9VYCPUF5DYbAgMBAAGj
UDBOMB0GA1UdDgQWBBTxI2YSnxnuDpwgxKOUgglmgiH/vDAfBgNVHSMEGDAWgBTx
I2YSnxnuDpwgxKOUgglmgiH/vDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQC30dcIPWlFfBEK/vNzG1Dx+BWkHCfd2GfmVc+VYSpmiTox13jKBOyEdQs4
xxB7HiESKkpAjQ0YC3mjE6F53NjK0VqdfzXhopg9i/pQJiaX0KTTcWIelsJNg2aM
s8GZ0nWSytcAqAV6oCnn+eOT/IqnO4ihgmaVIyhfYvRgXfPU/TuERtL9f8pAII44
jAVcy60MBZ1bCwQZcToZlfWCpO/8nLg4nnv4e3W9UeC6rDgWgpI6IXS3jikN/x3P
9JIVFcWLtsOLC+D/33jSV8XDM3qTTRv4i/M+mva6znOI89KcBjsEhX5AunSQZ4Zg
QkQTJi/td+5kVi00NXxlHYH5ztS1
-----END CERTIFICATE-----
EOM

echo 'cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no


[SSH]
accept = 444
connect = 127.0.0.1:22


[dropbear]
accept = 443
connect = 127.0.0.1:442'| sudo tee /etc/stunnel/stunnel.conf

}

install_proxy () {
cat << \socksopenvpn > /usr/local/sbin/proxy.py
#!/usr/bin/env python3
# encoding: utf-8
# SocksProxy By: Ykcir Ogotip Caayon
import socket, threading, thread, select, signal, sys, time
from os import system
system("clear")
#conexao
IP = '0.0.0.0'
try:
   PORT = int(sys.argv[1])
except:
   PORT = 8000
PASS = ''
BUFLEN = 8196 * 8
TIMEOUT = 60
MSG = 'Tk@network'
DEFAULT_HOST = '0.0.0.0:22'
RESPONSE = "HTTP/1.1 200 " + str(MSG) + "\r\n\r\n"

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
  self.threadsLock = threading.Lock()
  self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Conexao: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')

                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                if hostPort.startswith(IP):
                    self.method_CONNECT(hostPort)
                else:
                   self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
      pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 110
            else:
                port = 22

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''
        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
            try:
                        data = in_.recv(BUFLEN)
                        if data:
                    if in_ is self.target:
                        self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
                else:
                    break
            except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break



def main(host=IP, port=PORT):
    print "\033[0;34mâ”"*8,"\033[1;32m PROXY SOCKS","\033[0;34mâ”"*8,"\n"
    print "\033[1;33mIP:\033[1;32m " + IP
    print "\033[1;33mPORTA:\033[1;32m " + str(PORT) + "\n"
    print "\033[0;34mâ”"*10,"\033[1;32m StrongHold","\033[0;34mâ”\033[1;37m"*11,"\n"
    server = Server(IP, PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print '\nClosing...'
            server.close()
            break
if __name__ == '__main__':
    main()
socksopenvpn

screen -dmS proxy1 python /usr/local/sbin/proxy.py 8080
screen -dmS proxy2 python /usr/local/sbin/proxy.py 8000
screen -dmS proxyssh python /usr/local/sbin/proxy.py 8888

wget -O /usr/bin/badvpn-udpgw "https://apk.admin-boyes.com/setup/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
ps x | grep 'udpvpn' | grep -v 'grep' || screen -dmS udpvpn /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 10000 --max-connections-for-client 10 --client-socket-sndbuf 10000

}

install_newwebsocket () {
cat << \websocket > /usr/local/sbin/websocket.py
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
  LISTENING_PORT = sys.argv[1]
else:
  LISTENING_PORT = 80
#Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:442'
#RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\nContent-length: 1048576000000\r\n\r\n'
#RESPONSE = 'HTTP/1.1 200 Hello_World!\r\nContent-length: 0\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n'  # lint:ok
RESPONSE = 'HTTP/1.1 101 Switching Protocols \r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')

                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
      pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 110
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
            try:
                        data = in_.recv(BUFLEN)
                        if data:
                    if in_ is self.target:
                        self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
                else:
                    break
            except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT

    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

#######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()

websocket

}

install_cron () {

cat << \autostart > /bin/auto
#!/bin/bash

if nc -z localhost 80; then
    echo "WebSocket Running"
else
    echo "Starting Port 80"
    screen -dmS websocket python /usr/local/sbin/websocket.py 80
fi

if nc -z localhost 8080; then
    echo "SocksProxy running"
else
    echo "Starting Port 8080"
    screen -dmS proxy python /usr/local/sbin/proxy.py 8080
fi



if nc -z localhost 8000; then
    echo "SocksProxy running"
else
    echo "Starting Port 8000"
    screen -dmS proxy2 python /usr/local/sbin/proxy.py 8000
fi

if nc -z localhost 8888; then
    echo "SocksProxy running"
else
    echo "Starting Port 8888"
    screen -dmS proxyssh python /usr/local/sbin/proxy.py 8888
fi

if nc -z localhost 443; then
    echo "Stunnel running"
else
    echo "Starting Port 443"
    sudo systemctl start stunnel4
fi

if nc -z localhost 7300; then
    echo "badvpn running"
else
    echo "Starting Badvpn"
    screen -dmS udpvpn /bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 3
fi

sudo sync; echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a
echo "Ram Cleaned!"

autostart

crontab -r
echo "* * * * * /bin/bash /bin/auto >/dev/null 2>&1
* * * * * /bin/bash /root/auth.sh >/dev/null 2>&1" | crontab
}

iptablesrules () {
echo 'net.ipv4.ip_forward=1
' >> /etc/sysctl.conf
echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000
SELINUX=disabled
sysctl -p
}

serviceenable () {
update-rc.d cron enable
update-rc.d stunnel4 enable
service stunnel4 start
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/#ForwardToWall=yes/ForwardToWall=no/g' /etc/systemd/journald.conf
}

function Slowdns() {
rm -rf install; wget https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/install; chmod +x install; ./install
bash /etc/slowdns/slowdns-ssh
startdns
}

start_service(){
clear
echo 'Installing proxy.'
{
/usr/sbin/useradd -p $(openssl passwd -1 12345) -M bulala
history -c;
rm ~/install_server.sh
netstat -tupln

 echo -e " Success Installation"
 echo -e ""
 echo -e " Service Ports: "
 echo -e " OpenSSH: 22"
 echo -e " Stunnel: 443, 444,"
 echo -e " DropbearSSH: 442, 551"
 echo -e " Squid: 8000, 8080"
 echo -e " BadVPN-udpgw: 7200"
 echo -e ""
 echo -e " Websocket Service Ports: "
 echo -e ""
 echo -e " OpenSSH WS: 80"
 echo -e " OpenSSL WS: 443"
 echo -e ""
 echo -e " SlowDns Config:"
 echo -e ""
 echo -e " \e[92m Websocket DNS:\e[0m \e[97m: $MYDNS\e[0m"
 echo -e " \e[92m Slowdns:\e[0m \e[97m: 2222\e[0m" 
 echo -e " \e[92m SLOWCHAVE KEY:\e[0m \e[97m" && cat /root/server.pub
 echo -e " \e[92m YOUR NAMESERVER:\e[0m \e[97m" && cat nameserver.txt
 echo -e ""
 echo -e "\033[1;31m═══════════════════════════════════════════════════\033[0m"
}

system_package
modify_badvpn
install_firewall_kvm
install_rclocal
install_dropbear
install_stunnel
install_proxy
install_newwebsocket
install_cron
iptablesrules
serviceenable
Slowdns
start_service

