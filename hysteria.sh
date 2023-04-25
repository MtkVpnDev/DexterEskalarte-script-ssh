#!/bin/bash
#Script Variables
DOMAIN=admin-boyes.com
CF_ID=ericlaylay@gmail.com
CF_KEY=267f2cf11375260fa526109dcb9c630697815
CF_ZONE=ed5388f45740be5403f682843198efcd
MYIP=$(wget -qO- icanhazip.com);
server_ip=$(curl -s https://api.ipify.org)
timedatectl set-timezone Asia/Riyadh


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



install_hysteria(){
clear
echo 'Installing hysteria.'
{
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/apernet/hysteria/master/install_server.sh; chmod +x ~/install_server.sh; ./install_server.sh
} &>/dev/null
}

modify_hysteria(){


clear
echo 'modifying hysteria.'
{
rm -f /etc/hysteria/config.json

echo '{
   "listen": ":5666",
  "cert": "/etc/hysteria/hysteria.crt",
  "key": "/etc/hysteria/hysteria.key",
   "up_mbps": 100,
  "down_mbps": 100,
  "udpwindow": 196608,
  "disable_udp": false,
  "obfs": "noypi",
  "auth": {
    "mode": "passwords",
    "config": ["vpnnoypi", "vpnnoypi"]
  }
}
' >> /etc/hysteria/config.json

chmod 755 /etc/hysteria/config.json
chmod 755 /etc/hysteria/hysteria.crt
chmod 755 /etc/hysteria/hysteria.key

wget -O /usr/bin/badvpn-udpgw "https://apk.admin-boyes.com/setup/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
ps x | grep 'udpvpn' | grep -v 'grep' || screen -dmS udpvpn /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 10000 --max-connections-for-client 10 --client-socket-sndbuf 10000
}
}




create_hostname() {

clear

echo 'Creating hostname.'
{
cat << EOF > /etc/hysteria/hysteria.crt
-----BEGIN CERTIFICATE-----
MIIEDTCCA5OgAwIBAgIRAMv34LzMCBBkYpVynicsLYkwCgYIKoZIzj0EAwMwSzEL
MAkGA1UEBhMCQVQxEDAOBgNVBAoTB1plcm9TU0wxKjAoBgNVBAMTIVplcm9TU0wg
RUNDIERvbWFpbiBTZWN1cmUgU2l0ZSBDQTAeFw0yMzA0MDUwMDAwMDBaFw0yMzA3
MDQyMzU5NTlaMB8xHTAbBgNVBAMTFGNvOHouYWRtaW4tYm95ZXMuY29tMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAENj+S90/5JQNPsS2swnmmMdZ1O6koVCfM07OW
9ge62tFn9C7SKTnkM/zfT0QP5AWcr+UF2xDBdjCw8vEOk7EWraOCAoIwggJ+MB8G
A1UdIwQYMBaAFA9r5kvOOUeu9n6QHnnwMJGSyF+jMB0GA1UdDgQWBBQZRj2HNe6H
9bjPU+ztOYy/U48W1zAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0gBEIwQDA0BgsrBgEEAbIx
AQICTjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZn
gQwBAgEwgYgGCCsGAQUFBwEBBHwwejBLBggrBgEFBQcwAoY/aHR0cDovL3plcm9z
c2wuY3J0LnNlY3RpZ28uY29tL1plcm9TU0xFQ0NEb21haW5TZWN1cmVTaXRlQ0Eu
Y3J0MCsGCCsGAQUFBzABhh9odHRwOi8vemVyb3NzbC5vY3NwLnNlY3RpZ28uY29t
MIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcArfe++nz/EMiLnT2cHj4YarRnKV3P
sQwkyoWGNOvcgooAAAGHUkF6gAAABAMASDBGAiEA4xPVTrsfgkBDiIbEbQKD69gL
3LNfD7+SerIBbK0QaXQCIQCCU1g/T7O0/d4miLMdw+GyXNqF7H717tEOG0nBTqIh
+QB3AHoyjFTYty22IOo44FIe6YQWcDIThU070ivBOlejUutSAAABh1JBetcAAAQD
AEgwRgIhAKh5HzrFvXsalNny0hMx24SYqPnOl9NmssAgBZxs6ojHAiEAqgW+AIL8
7a1nVKYha5RbhVTuL+mGxhDdJWkBmTC8GGMwHwYDVR0RBBgwFoIUY284ei5hZG1p
bi1ib3llcy5jb20wCgYIKoZIzj0EAwMDaAAwZQIwJRQn4KXfwSaTAVakLu7AsqRT
QQUJGrc5V1Pz1WxQfHhT6QntsL84220qrqxdO8W7AjEArTMSTdDE1B7XcSikd77S
W653OqjziWp3h7PlR1SECYW4uftjTGvsJLxtPfIFPTBG
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDhTCCAwygAwIBAgIQI7dt48G7KxpRlh4I6rdk6DAKBggqhkjOPQQDAzCBiDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl
eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT
JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjAwMTMw
MDAwMDAwWhcNMzAwMTI5MjM1OTU5WjBLMQswCQYDVQQGEwJBVDEQMA4GA1UEChMH
WmVyb1NTTDEqMCgGA1UEAxMhWmVyb1NTTCBFQ0MgRG9tYWluIFNlY3VyZSBTaXRl
IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENkFhFytTJe2qypTk1tpIV+9QuoRk
gte7BRvWHwYk9qUznYzn8QtVaGOCMBBfjWXsqqivl8q1hs4wAYl03uNOXgFu7iZ7
zFP6I6T3RB0+TR5fZqathfby47yOCZiAJI4go4IBdTCCAXEwHwYDVR0jBBgwFoAU
OuEJhtTPGcKWdnRJdtzgNcZjY5owHQYDVR0OBBYEFA9r5kvOOUeu9n6QHnnwMJGS
yF+jMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQW
MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAiBgNVHSAEGzAZMA0GCysGAQQBsjEBAgJO
MAgGBmeBDAECATBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVz
dC5jb20vVVNFUlRydXN0RUNDQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYI
KwYBBQUHAQEEajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5j
b20vVVNFUlRydXN0RUNDQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6
Ly9vY3NwLnVzZXJ0cnVzdC5jb20wCgYIKoZIzj0EAwMDZwAwZAIwJHBUDwHJQN3I
VNltVMrICMqYQ3TYP/TXqV9t8mG5cAomG2MwqIsxnL937Gewf6WIAjAlrauksO6N
UuDdDXyd330druJcZJx0+H5j5cFOYBaGsKdeGW7sCMaR2PsDFKGllas=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID0zCCArugAwIBAgIQVmcdBOpPmUxvEIFHWdJ1lDANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGqxUWqn5aCPnetUkb1PGWthL
q8bVttHmc3Gu3ZzWDGH926CJA7gFFOxXzu5dP+Ihs8731Ip54KODfi2X0GHE8Znc
JZFjq38wo7Rw4sehM5zzvy5cU7Ffs30yf4o043l5o4HyMIHvMB8GA1UdIwQYMBaA
FKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1
xmNjmjAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAI
MAYGBFUdIAAwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5j
b20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEM
BQADggEBABns652JLCALBIAdGN5CmXKZFjK9Dpx1WywV4ilAbe7/ctvbq5AfjJXy
ij0IckKJUAfiORVsAYfZFhr1wHUrxeZWEQff2Ji8fJ8ZOd+LygBkc7xGEJuTI42+
FsMuCIKchjN0djsoTI0DQoWz4rIjQtUfenVqGtF8qmchxDM6OW1TyaLtYiKou+JV
bJlsQ2uRl9EMC5MCHdK8aXdJ5htN978UeAOwproLtOGFfy/cQjutdAFI3tZs4RmY
CV4Ks2dH/hzg1cEo70qLRDEmBDeNiXQ2Lu+lIg+DdEmSx/cQwgwp+7e9un/jX9Wf
8qn0dNW44bOwgeThpWOjzOoEeJBuv/c=
-----END CERTIFICATE-----
EOF


cat << EOF > /etc/hysteria/hysteria.key
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHMYjq7r4SkBNVD2awZIOuubwRhCifFQCogUZSJJ8r7RoAoGCCqGSM49
AwEHoUQDQgAENj+S90/5JQNPsS2swnmmMdZ1O6koVCfM07OW9ge62tFn9C7SKTnk
M/zfT0QP5AWcr+UF2xDBdjCw8vEOk7EWrQ==
-----END EC PRIVATE KEY-----
EOF


}
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
iptables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 20000:50000 -j DNAT --to-destination :5666
iptables-save > /etc/iptables_rules.v4
ip6tables-save > /etc/iptables_rules.v6
}
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
service hysteria-server restart
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
exit 0' >> /etc/rc.local
    sudo chmod +x /etc/rc.local
    systemctl daemon-reload
    sudo systemctl enable tknetwork
    sudo systemctl start tknetwork.service
  }
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

start_service(){
clear
echo 'Installing proxy.'
{
systemctl start hysteria-server.service
systemctl enable hysteria-server.service
 /usr/sbin/useradd -p $(openssl passwd -1 12345) -M bulala
 history -c;
 rm ~/install_server.sh
 rm ~/hysteria.sh
 netstat -tupln
 reboot
}
}


system_package
install_hysteria
modify_hysteria
create_hostname
install_firewall_kvm
install_rclocal
install_dropbear
install_stunnel
install_proxy
install_newwebsocket
install_cron
iptablesrules
serviceenable
start_service
