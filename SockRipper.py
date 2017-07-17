import argparse
import socket


class SockRipper:
    def conn(self, sock, port):
        # __function__ = "conn"
        # print("SockRipper.{}".format(__function__))

        try:
            sock.settimeout(3)
            sock.connect((self.ip, port))
            print('{} Opened'.format(port))
            self.bannerGrab(sock)
        except socket.timeout:
            print('{} Closed'.format(port))

    def portScan_TCP(self):
        # __function__ = "portScan_TCP"
        # print("SockRipper.{}".format(__function__))

        if type(self.port) is int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                self.conn(sock, self.port)
        else:
            for p in self.port:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    self.conn(sock, int(p))

    def portScan_UDP(self):
        # __function__ = "portScan_UDP"
        # print("SockRipper.{}".format(__function__))

        if type(self.port) is int:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                self.conn(sock, self.port)
        else:
            for p in self.port:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    self.conn(sock, int(p))

    def bannerGrab(self, sock):
        __function__ = "bannerGrab_TCP"
        print("SockRipper.{}".format(__function__))
        # TODO bannerGrab_TCP

        sock.sendall(str.encode('GET /\r\n'))
        data = sock.recv(1024).decode('utf-8')
        print(data)

    def resolve_IP(self):
        # __function__ = "resolve_IP"
        # print("SockRipper.{}".format(__function__))
        self.hostname = socket.gethostbyaddr(self.ip)[0]

    def resolve_DNS(self):
        # __function__ = "resolve_DNS"
        # print("SockRipper.{}".format(__function__))
        self.ip = socket.gethostbyname(self.hostname)

    def load_VulnFile(self):
        __function__ = "load_VulnFile"
        print("SockRipper.{}".format(__function__))
        # TODO load_VulnFile

    def compare_banners(self):
        __function__ = "compare_banners"
        print("SockRipper.{}".format(__function__))
        # TODO compare_banners

    def save_IP(self):
        __function__ = "save_IP"
        print("SockRipper.{}".format(__function__))
        # TODO save_IP

    def __init__(self, ip=None, host=None, mode='TCP', port=[21, 22, 80, 443], **kwargs):
        # Function Signature
        # __function__ = "__init__"
        # print("SockRipper.{}".format(__function__))

        # Variables,
        self.ip = ip
        self.mode = mode
        self.hostname = host
        self.port = port
        self.port_status_tcp = {}  # {'PortNO': 'Status' 'Banner'}
        self.port_status_udp = {}  # {'PortNO': 'Status' 'Banner'}

        # Fill all Variables
        if self.ip is None:
            self.resolve_DNS()
        else:
            self.resolve_IP()

        print(self.__dict__)

        # Decide Which Scan Mode
        method_to_call = getattr(self, 'portScan_' + mode.upper())
        method_to_call()

        # Methods to Finish
        # self.bannerGrab_TCP()
        # self.load_VulnFile()
        # self.compare_banners()
        # self.save_IP()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This is SockRipper a Network Scanning Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-ip', help='IP To Be Scanned')
    group.add_argument('-host', help='Hostname to be Scanned')
    group.add_argument('-ipFile', help='File with list of IPs to be Scanned')
    group.add_argument('-hostFile', help='File with list of HostNames to be Scanned')
    parser.add_argument('-p', help='Specify port/s to scan.')
    parser.add_argument('-mode', help='TCP/UDP, default: TCP')
    parser.add_argument('--onlyScan', help='Will Only Perform Port Sweep, default: Banner Grab on Open Port', action='store_true')
    args = parser.parse_args()

    if type(args.p) is not int and args.p:
        if ', ' in args.p:
            args.p = args.p.split(', ')
        elif '-' in args.p:
            args.p = range(int(args.p.split('-')[0]), int(args.p.split('-')[1]))
        else:
            args.p = int(args.p)

    if args.ip:
        if args.mode and args.p:
            SockRipper(ip=args.ip, mode=args.mode, port=args.p)
        elif args.mode:
            SockRipper(ip=args.ip, mode=args.mode)
        elif args.p:
            SockRipper(ip=args.ip, port=args.p)
        else:
            SockRipper(ip=args.ip)
    elif args.host:
        if args.mode and args.p:
            SockRipper(host=args.host, mode=args.mode, port=args.p)
        elif args.mode:
            SockRipper(host=args.host, mode=args.mode)
        elif args.p:
            SockRipper(host=args.host, port=args.p)
        else:
            SockRipper(host=args.host)
    elif args.ipFile:
        with open(args.ipFile, 'r') as file:
            for ip in file:
                if args.mode and args.p:
                    SockRipper(ip=ip.strip('\n'), mode=args.mode, port=args.p)
                elif args.mode:
                    SockRipper(ip=ip.strip('\n'), mode=args.mode)
                elif args.p:
                    SockRipper(ip=ip.strip('\n'), port=args.p)
                else:
                    SockRipper(ip=ip.strip('\n'))
    elif args.hostFile:
        with open(args.ipFile, 'r') as file:
            for host in file:
                if args.mode and args.p:
                    SockRipper(host=host.strip('\n'), mode=args.mode, port=args.p)
                elif args.mode:
                    SockRipper(host=host.strip('\n'), mode=args.mode)
                elif args.p:
                    SockRipper(host=host.strip('\n'), port=args.p)
                else:
                    SockRipper(host=host.strip('\n'))
