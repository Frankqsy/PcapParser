package org.daisy.stevin.pcap.packet;


import org.daisy.stevin.pcap.header.EthernetHeader;
import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * @author stevin.qi
 *
 */
public class EthernetPacket extends AbstractPacket {
    private EthernetHeader header;

    public EthernetPacket(EthernetHeader header, byte[] payload) {
        super(payload);
        this.header = header;
    }

    @Override
    public EthernetHeader getHeader() {
        return header;
    }

    public static EthernetPacket newPacket(byte[] packetBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(packetBytes, offset, length, EthernetHeader.BYTE_LENGTH))) {
            return null;
        }

        byte[] dataHeaderBytes = new byte[EthernetHeader.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, dataHeaderBytes, 0, EthernetHeader.BYTE_LENGTH);
        offset += EthernetHeader.BYTE_LENGTH;
        EthernetHeader dataHeader = EthernetHeader.newInstance(dataHeaderBytes, 0, dataHeaderBytes.length);
        if (dataHeader == null) {
            System.out.println(String.format("EthernetHeader deocde error,EthernetPacket bytes:[%s]", BytesUtil.byteArrayToHexString(packetBytes, ",")));
            return null;
        }

        byte[] payLoad = new byte[length - EthernetHeader.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, payLoad, 0, payLoad.length);

        return new EthernetPacket(dataHeader, payLoad);
    }

}
