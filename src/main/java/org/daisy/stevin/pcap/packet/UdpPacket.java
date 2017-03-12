package org.daisy.stevin.pcap.packet;

import org.daisy.stevin.pcap.header.UdpHeader;
import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * 
 * @author stevin.qi
 *
 */
public class UdpPacket extends AbstractPacket {
    private UdpHeader header;

    public UdpPacket(UdpHeader header, byte[] payload) {
        super(payload);
        this.header = header;
    }

    @Override
    public UdpHeader getHeader() {
        return header;
    }

    public static UdpPacket newPacket(byte[] packetBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(packetBytes, offset, length, UdpHeader.BYTE_LENGTH))) {
            return null;
        }

        byte[] dataHeaderBytes = new byte[UdpHeader.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, dataHeaderBytes, 0, UdpHeader.BYTE_LENGTH);
        offset += UdpHeader.BYTE_LENGTH;
        UdpHeader dataHeader = UdpHeader.newInstance(dataHeaderBytes, 0, dataHeaderBytes.length);
        if (dataHeader == null) {
            System.out.println(String.format("UdpHeader decode error, UdpPacket bytes:[%s]", BytesUtil.byteArrayToHexString(packetBytes, ",")));
            return null;
        }

        byte[] payLoad = new byte[Math.min(length, dataHeader.getLength()) - UdpHeader.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, payLoad, 0, payLoad.length);

        return new UdpPacket(dataHeader, payLoad);
    }
}
