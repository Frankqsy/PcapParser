package org.daisy.stevin.pcap.handler;

import org.daisy.stevin.pcap.packet.EthernetPacket;
import org.daisy.stevin.pcap.packet.IpV4Packet;
import org.daisy.stevin.pcap.packet.PcapPacket;
import org.daisy.stevin.pcap.packet.TcpPacket;
import org.daisy.stevin.pcap.util.BytesUtil;
import org.testng.annotations.Test;

public class PcapsTest {

    @Test(enabled = false)
    public void openOfflineFile() {
        String inputPath = "/Users/wireshark.cap";
        PcapHandle handle = Pcaps.openOfflineFile(inputPath);
        if (handle == null) {
            return;
        }
        System.out.println(handle.getFileHeader());
        for (int i = 0; i < 1; i++) {
            System.out.println("packet number:" + (i + 1));
            PcapPacket packet = handle.nextPacket();
            if (packet == null) {
                break;
            }
            System.out.println(packet.getHeader());
            byte[] ethernetBytes = packet.getPayload();
            System.out.println(BytesUtil.byteArrayToHexString(ethernetBytes, ","));
            EthernetPacket ethernet = PacketDecoder.getEthernet(ethernetBytes);
            System.out.println(ethernet.getHeader());
            System.out.println(BytesUtil.byteArrayToHexString(ethernet.getPayload(), ","));
            IpV4Packet ipV4Packet = PacketDecoder.getIpV4PacketFromEthernet(ethernet);
            System.out.println(ipV4Packet.getHeader());
            System.out.println(BytesUtil.byteArrayToHexString(ipV4Packet.getPayload(), ","));
            TcpPacket tcpPacket = PacketDecoder.getTcpPacketFromIpV4(ipV4Packet);
            System.out.println(tcpPacket.getHeader());
            byte[] pgBytes = PacketDecoder.getTcpPayload(tcpPacket);
            System.out.println(BytesUtil.byteArrayToHexString(pgBytes, ","));
            System.out.println("\n");
        }

        handle.close();

    }
}
