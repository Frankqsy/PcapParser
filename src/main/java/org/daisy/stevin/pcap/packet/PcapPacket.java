package org.daisy.stevin.pcap.packet;

import org.daisy.stevin.pcap.header.PcapDataHeader;
import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * 
 * @author stevin.qi
 *
 */
public class PcapPacket extends AbstractPacket {
    private PcapDataHeader header;

    public PcapPacket(PcapDataHeader header, byte[] payload) {
        super(payload);
        this.header = header;
    }

    @Override
    public PcapDataHeader getHeader() {
        return header;
    }

    public static PcapPacket newPacket(byte[] packetBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(packetBytes, offset, length, PcapDataHeader.BYTE_LENGTH))) {
            return null;
        }

        byte[] dataHeaderBytes = new byte[PcapDataHeader.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, dataHeaderBytes, 0, PcapDataHeader.BYTE_LENGTH);
        offset += PcapDataHeader.BYTE_LENGTH;
        PcapDataHeader dataHeader = PcapDataHeader.newInstance(dataHeaderBytes, 0, dataHeaderBytes.length);
        if (dataHeader == null) {
            System.out.println(String.format("PcapDataHeader decode error, PcapPacket bytes:[%s]", BytesUtil.byteArrayToHexString(packetBytes, ",")));
            return null;
        }

        byte[] payLoad = new byte[Math.min(length - PcapDataHeader.BYTE_LENGTH, dataHeader.getCaplen())];
        System.arraycopy(packetBytes, offset, payLoad, 0, payLoad.length);

        return new PcapPacket(dataHeader, payLoad);
    }

}
