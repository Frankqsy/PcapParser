package org.daisy.stevin.pcap.packet;

import org.daisy.stevin.pcap.header.TcpHeader;
import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * 
 * @author stevin.qi
 *
 */
public class TcpPacket extends AbstractPacket {
    private TcpHeader header;

    public TcpPacket(TcpHeader header, byte[] payload) {
        super(payload);
        this.header = header;
    }

    @Override
    public TcpHeader getHeader() {
        return header;
    }

    public static TcpPacket newPacket(byte[] packetBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(packetBytes, offset, length, TcpHeader.BYTE_LENGTH))) {
            return null;
        }

        byte[] dataHeaderBytes = new byte[TcpHeader.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, dataHeaderBytes, 0, TcpHeader.BYTE_LENGTH);
        TcpHeader dataHeader = TcpHeader.newInstance(dataHeaderBytes, 0, dataHeaderBytes.length);
        if (dataHeader == null) {
            System.out.println(String.format("TcpHeader decode error, TcpPacket bytes:[%s]", BytesUtil.byteArrayToHexString(packetBytes, ",")));
            return null;
        }

        // 假设length是正确的tcp数据包长度，因为正常情况下，IpPacket包里有正确的长度，截取出来的payload一定是正确的
        byte[] payLoad = new byte[Math.max(0, length - dataHeader.realHeadLength())];
        if (payLoad.length > 0) {
            offset += dataHeader.realHeadLength();
            System.arraycopy(packetBytes, offset, payLoad, 0, payLoad.length);
        }

        return new TcpPacket(dataHeader, payLoad);
    }

}
