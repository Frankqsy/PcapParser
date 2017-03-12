package org.daisy.stevin.pcap.handler;

import org.daisy.stevin.pcap.header.EthernetHeader;
import org.daisy.stevin.pcap.header.IpV4Header;
import org.daisy.stevin.pcap.header.TcpHeader;
import org.daisy.stevin.pcap.packet.EthernetPacket;
import org.daisy.stevin.pcap.packet.IpV4Packet;
import org.daisy.stevin.pcap.packet.TcpPacket;
import org.daisy.stevin.pcap.util.NoThrow;

/**
 * 用于解析packet的辅助类
 * 
 * @author stevin.qi
 *
 */
public class PacketDecoder {
    public static EthernetPacket getEthernet(byte[] ethernetPacket) {
        return ethernetPacket == null ? null : NoThrow.execute(() -> EthernetPacket.newPacket(ethernetPacket, 0, ethernetPacket.length), (e) -> null);
    }

    public static EthernetHeader getEthernetHeader(byte[] ethernetPacket) {
        EthernetPacket ethernet = getEthernet(ethernetPacket);
        return ethernet == null ? null : ethernet.getHeader();
    }

    public static byte[] getEthernetPayload(byte[] ethernetPacket) {
        EthernetPacket ethernet = getEthernet(ethernetPacket);
        return getEthernetPayload(ethernet);
    }

    public static byte[] getEthernetPayload(EthernetPacket ethernetPacket) {
        return ethernetPacket == null || ethernetPacket.getPayload() == null ? null : ethernetPacket.getPayload();
    }

    public static IpV4Packet getIpV4Packet(byte[] ipV4Packet) {
        return ipV4Packet == null ? null : NoThrow.execute(() -> IpV4Packet.newPacket(ipV4Packet, 0, ipV4Packet.length), (e) -> null);
    }

    public static IpV4Packet getIpV4PacketFromEthernet(EthernetPacket ethernetPacket) {
        byte[] ipV4Packet = getEthernetPayload(ethernetPacket);
        return getIpV4Packet(ipV4Packet);
    }

    public static IpV4Packet getIpV4PacketFromEthernet(byte[] ethernetPacket) {
        EthernetPacket ethernet = getEthernet(ethernetPacket);
        return getIpV4PacketFromEthernet(ethernet);
    }

    public static IpV4Header getIpV4Header(byte[] ipV4Packet) {
        IpV4Packet ipV4 = getIpV4Packet(ipV4Packet);
        return ipV4 == null ? null : ipV4.getHeader();
    }

    public static byte[] getIpV4Payload(byte[] ipV4Packet) {
        IpV4Packet ipV4 = getIpV4Packet(ipV4Packet);
        return getIpV4Payload(ipV4);
    }

    public static byte[] getIpV4Payload(IpV4Packet ipV4) {
        return ipV4 == null || ipV4.getPayload() == null ? null : ipV4.getPayload();
    }

    public static byte[] getIpV4PayloadFromEthernet(byte[] ethernetPacket) {
        IpV4Packet ipV4 = getIpV4PacketFromEthernet(ethernetPacket);
        return getIpV4Payload(ipV4);
    }

    public static TcpPacket getTcpPacket(byte[] tcpPacket) {
        return tcpPacket == null ? null : NoThrow.execute(() -> TcpPacket.newPacket(tcpPacket, 0, tcpPacket.length), (e) -> null);
    }

    public static TcpPacket getTcpPacketFromIpV4(IpV4Packet ipV4) {
        byte[] tcpPacket = getIpV4Payload(ipV4);
        return getTcpPacket(tcpPacket);
    }

    public static TcpPacket getTcpPacketFromIpV4(byte[] ipV4Packet) {
        IpV4Packet ipV4 = getIpV4Packet(ipV4Packet);
        return getTcpPacketFromIpV4(ipV4);
    }

    public static TcpPacket getTcpPacketFromEthernetUsedIpV4(byte[] ethernetPacket) {
        IpV4Packet ipV4 = getIpV4PacketFromEthernet(ethernetPacket);
        return getTcpPacketFromIpV4(ipV4);
    }

    public static TcpHeader getTcpHeader(byte[] tcpPacket) {
        TcpPacket tcp = getTcpPacket(tcpPacket);
        return tcp == null ? null : tcp.getHeader();
    }

    public static byte[] getTcpPayload(byte[] tcpPacket) {
        TcpPacket tcp = getTcpPacket(tcpPacket);
        return getTcpPayload(tcp);
    }

    public static byte[] getTcpPayload(TcpPacket tcpPacket) {
        return tcpPacket == null || tcpPacket.getPayload() == null ? null : tcpPacket.getPayload();
    }

    public static byte[] getTcpPayloadFromIpV4(byte[] ipV4Packet) {
        TcpPacket tcpPacket = getTcpPacketFromIpV4(ipV4Packet);
        return getTcpPayload(tcpPacket);
    }

    public static byte[] getTcpPayloadFromIpV4(IpV4Packet ipV4Packet) {
        TcpPacket tcpPacket = getTcpPacketFromIpV4(ipV4Packet);
        return getTcpPayload(tcpPacket);
    }

    public static byte[] getTcpPayloadFromEthernetUsedIpV4(byte[] ethernetPacket) {
        IpV4Packet ipV4Packet = getIpV4PacketFromEthernet(ethernetPacket);
        return getTcpPayloadFromIpV4(ipV4Packet);
    }
}
