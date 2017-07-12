class SockRipper:
    def portScan_TCP(self):
        __function__ = "portScan_TCP"
        print("SockRipper.{}".format(__function__))

    def portScan_UDP(self):
        __function__ = "portScan_UDP"
        print("SockRipper.{}".format(__function__))

    def bannerGrab_TCP(self):
        __function__ = "bannerGrab_TCP"
        print("SockRipper.{}".format(__function__))

    def bannerGrab_UDP(self):
        __function__ = "bannerGrab_UDP"
        print("SockRipper.{}".format(__function__))

    def resolve_IP(self):
        __function__ = "resolve_IP"
        print("SockRipper.{}".format(__function__))

    def resolve_DNS(self):
        __function__ = "resolve_DNS"
        print("SockRipper.{}".format(__function__))

    def load_VulnFile(self):
        __function__ = "load_VulnFile"
        print("SockRipper.{}".format(__function__))

    def compare_banners(self):
        __function__ = "compare_banners"
        print("SockRipper.{}".format(__function__))

    def save_IP(self):
        __function__ = "save_IP"
        print("SockRipper.{}".format(__function__))

    def __init__(self, ip, mode):
        # Function Signature
        __function__ = "__init__"
        print("SockRipper.{}".format(__function__))

        # Variables
        self.ip = ip
        self.mode = mode
        print(self.__dict__)

        # Methods
        self.portScan_TCP()
        self.portScan_UDP()
        self.bannerGrab_TCP()
        self.bannerGrab_UDP()
        self.resolve_IP()
        self.resolve_DNS()
        self.load_VulnFile()
        self.compare_banners()
        self.save_IP()

if __name__ == '__main__':
    SockRipper('1', 'TCP')
