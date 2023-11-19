import socket
import argparse
import sys
import threading


port_server = {
    20: "FTP服务",
    21: "FTP服务",
    22: "SSH服务",
    23: "Telnet服务",
    25: "SMTP简单邮件传输协议",
    43: "whois服务",
    53: "DNS服务",
    67: "DHCP服务",
    68: "DHCP服务",
    69: "TFTP服务",
    80: "WEB服务",
    90: "WEB服务",
    110: "POP3邮件服务",
    137: "SMB/CIFS服务",
    138: "SMB/CIFS服务",
    139: "SMB/CIFS服务",
    445: "SMB/CIFS服务",
    143: "IMAP协议",
    161: "Snmp服务",
    162: "Snmp服务",
    389: "LDAP目录访问协议",
    443: "HTTPS服务",
    512: "Linux Rexec服务",
    513: "Linux Rexec服务",
    514: "Linux Rexec服务",
    873: "Rsync",
    1025: "RPCNFC",
    1080: "socket",
    1099: "Java RMI",
    1352: "Lotus domino邮件服务",
    1433: "SQL Server数据库",
    1434: "微软SQL Server未公开的监听端口",
    1521: "Oracle数据库",
    2049: "NFS服务",
    2181: "ZooKeeper",
    2375: "Docker",
    2601: "Zebra",
    3128: "squid",
    3306: "MySQL数据库",
    3389: "Windows远程桌面服务",
    3690: "SVN服务",
    4440: "Rundeck",
    4560: "log4j SocketServer",
    4750: "BMC",
    4848: "GlassFish控制台",
    5000: "SysBase/DB2数据库",
    5432: "PostGreSQL数据库",
    5632: "PcAnywhere服务",
    5900: "VNC服务",
    5901: "VNC服务",
    5984: "CouchDB",
    6379: "Redis数据库",
    7001: "Weblogic",
    7002: "Weblogic",
    7180: "Cloudera manager",
    8069: "Zabbix服务",
    8080: "Tomcat, Jetty, Jenkins服务",
    8089: "Tomcat, Jetty, Jenkins服务",
    8888: "宝塔默认端口",
    8161: "Apache ActiveMQ后台管理系统",
    9000: "fastcgi",
    9001: "Supervisord",
    9043: "WebSphere",
    9090: "WebSphere",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    10000: "Webmin-Web控制面板",
    10001: "JmxRemoteLifecycleListener",
    10002: "JmxRemoteLifecycleListener",
    11211: "Memcached",
    27017: "MongoDB数据库",
    27018: "MongoDB数据库",
    50000: "SAP Management Console",
    50070: "Hadoop",
    60020: "hbase.regionserver.port",
    60030: "hbase.regionserver.info.port"
}

keys = list(port_server.keys())
keys_str = ', '.join(str(key) for key in keys)

def tcp_scan(ip, port, open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        open_ports.append(port)
    sock.close()

def udp_scan(ip, port, open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(bytes("Hello", "utf-8"), (ip, port))
        sock.recvfrom(1024)
    except socket.error:
        pass
    else:
        open_ports.append(port)
    sock.close()

def portscan(ip, ports, protocol, rate):
    threads = []
    open_ports = []
    for i, port in enumerate(ports):
        sys.stdout.write(f"\rScanning ports: {i / len(ports) * 100:.2f}%")
        sys.stdout.flush()
        if protocol == "tcp":
            t = threading.Thread(target=tcp_scan, args=(ip, port, open_ports))
        elif protocol == "udp":
            t = threading.Thread(target=udp_scan, args=(ip, port, open_ports))
        threads.append(t)
        t.start()
        if len(threads) >= rate:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()
    print("\nScan completed!")
    for port in open_ports:
        if port in keys:
            print(f"[+] open port:{port} server:{port_server[port]}")
        else:
            print(f"[+] open port:{port}")

def parse_ports(port_string):
    if "-" in port_string:
        start, end = map(int, port_string.split("-"))
        return list(range(start, end + 1))
    elif "," in port_string:
        return list(map(int, port_string.split(",")))
    else:
        return [int(port_string)]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port scanner")
    parser.add_argument("ip", help="IP address to scan")
    parser.add_argument("-p", "--ports", type=parse_ports, default=keys_str, help="Ports to scan")
    parser.add_argument("-r", "--rate", type=int, default=100, help="Scan rate")
    parser.add_argument("-T", "--tcp", action="store_true", help="Perform TCP scan")
    parser.add_argument("-U", "--udp", action="store_true", help="Perform UDP scan")
    args = parser.parse_args()

    if args.tcp and args.udp:
        print("Please select either TCP or UDP scan.")
    elif args.tcp:
        portscan(args.ip, args.ports, "tcp", args.rate)
    elif args.udp:
        portscan(args.ip, args.ports, "udp", args.rate)
    else:
        portscan(args.ip, args.ports, "tcp", args.rate)
