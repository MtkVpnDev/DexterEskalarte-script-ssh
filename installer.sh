#!/bin/bash

Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
Purple="\033[0;35m"
RedBG="\033[41;37m"
Font="\033[0m"
PurpleBG="\033[45;37m"
YellowBG="\033[43m"

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
    


function bonscript() {
#Bon-chan autoscript installer
wget -O ssh.sh "https://raw.githubusercontent.com/MtkVpnDev/DexterEskalarte-script-ssh/main/ssh.sh" && chmod +x ~/ssh.sh && sed -i -e 's/\r$//' ~/ssh.sh && ./ssh.sh
}

 bonscript
 
 # I'm setting Some Squid workarounds to prevent Privoxy's overflowing file descriptors that causing 50X error when clients trying to connect to your proxy server(thanks for this trick @homer_simpsons)
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y

# Squid Ports (must be 1024 or higher)

 cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all
http_port 0.0.0.0:8000
http_port 0.0.0.0:8080
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

 sed -i "s|SquidCacheHelper|8000|g" /etc/squid/squid.conf
 sed -i "s|SquidCacheHelper|8080|g" /etc/squid/squid.conf

 systemctl restart squid
 

# script for SSH Websocket

function service() {
cat << PTHON > /usr/sbin/yakult
#!/usr/bin/python
import socket, threading, thread, select, signal, sys, time, getopt
# Listen
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
  LISTENING_PORT = sys.argv[1]
else:
  LISTENING_PORT = 80
# Pass
PASS = ''
# CONST
BUFLEN = 4096 * 4
TIMEOUT = 3600
DEFAULT_HOST = '127.0.0.1:550'
RESPONSE = 'HTTP/1.1 101 <font color="red">Dexter Eskalarte</font>\r\n\r\nContent-Length: 104857600000\r\n\r\n'
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
                port = 443
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
PTHON
}

function service1() {
cat << END > /lib/systemd/system/yakult.service
[Unit]
Description=Yakult
Documentation=https://google.com
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/bin/python -O /usr/sbin/yakult
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
END
}


#changing SSH Banner
SSH_Banner='https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/SshBanner'

 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner
 systemctl restart ssh
 systemctl restart sshd
 systemctl restart dropbear
 
function setting() {
service ssh restart
service sshd restart
service dropbear restart
systemctl daemon-reload
systemctl enable yakult
systemctl restart yakult
systemctl daemon-reload
systemctl stop syslog
systemctl disable syslog
systemctl stop syslog.socket
systemctl disable syslog.socket
}

service
service1
setting

#timedatectl set-timezone Asia/Manila
#write out current crontab
#crontab -l > mycron
#echo new cron into cron file
#echo -e "0 3 * * * rm -rf /var/log/*" >> mycron
#echo -e "0 3 * * * /sbin/reboot >/dev/null 2>&1" >> mycron
#install new cron file
#crontab mycron
#service cron restart
#echo '0 3 * * * rm -rf /var/log/*' >> /etc/cron.d/mycron
#echo '0 3 * * * /sbin/reboot >/dev/null 2>&1' >> /etc/cron.d/mycron
#service cron restart



bash /etc/profile.d/bonv.sh
systemctl restart squid.service
 echo -e "\033[1;31m═══════════════════════════════════════════════════\033[0m"
echo '                                                              
    ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗        
    ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗       
    ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝       
    ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗       
    ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║       
 '
echo -e "\033[1;31m═══════════════════════════════════════════════════\033[0m"
 
 echo -e " Success Installation"
 echo -e ""
 echo -e " Service Ports: "
 echo -e " OpenSSH: 225, 22"
 echo -e " Stunnel: 443, 444, 587"
 echo -e " DropbearSSH: 550, 555"
 echo -e " OpenVPN: 25222(UDP), 110(TCP)"
 echo -e " OpenVPN EC: 25980(TCP), 25985(UDP)"
 echo -e " Squid: 8000, 8080"
 echo -e " Webmin: 10000"
 echo -e " BadVPN-udpgw: 7100, 7200, 7300"
 echo -e " NGiNX: 86"
 echo -e ""
 echo -e " NEW! OHPServer builds"
 echo -e " (Good for Payload bugging and any related HTTP Experiments)"
 echo -e ""
 echo -e " OHP+Dropbear: 8085"
 echo -e " OHP+OpenSSH: 8086"
 echo -e " OHP+OpenVPN: 8087"
 echo -e " OHP+OpenVPN Elliptic Curve: 8088"
 echo -e ""
 echo -e " Websocket Service Ports: "
 echo -e ""
 echo -e " \e[92m Websocket DNS:\e[0m \e[97m: $MYDNS\e[0m"
 echo -e ""
 echo -e " OpenSSH WS: 80"
 echo -e " OpenSSL WS: 443"
 echo -e " OpenVPN WS: 81"
 echo -e " OpenSSL WS: 587"
 echo -e ""
 echo -e " OpenVPN Configs Download site"
 echo -e " http://$IPADDR:86"
 echo -e ""
 echo -e "\033[1;31m═══════════════════════════════════════════════════\033[0m"
