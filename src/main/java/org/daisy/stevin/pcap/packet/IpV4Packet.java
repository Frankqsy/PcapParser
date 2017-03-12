package org.daisy.stevin.pcap.packet;

import org.daisy.stevin.pcap.header.IpV4Header;
import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * 
 * @author stevin.qi
 *
 */
public class IpV4Packet extends AbstractPacket {
    private IpV4Header header;

    protected IpV4Packet(IpV4Header header, byte[] payload) {
        super(payload);
        this.header = header;
    }

    @Override
    public IpV4Header getHeader() {
        return header;
    }

    public static IpV4Packet newPacket(byte[] packetBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(packetBytes, offset, length, IpV4Header.BYTE_LENGTH))) {
            return null;
        }

        byte[] dataHeaderBytes = new byte[IpV4Header.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, dataHeaderBytes, 0, IpV4Header.BYTE_LENGTH);
        offset += IpV4Header.BYTE_LENGTH;
        IpV4Header dataHeader = IpV4Header.newInstance(dataHeaderBytes, 0, dataHeaderBytes.length);
        if (dataHeader == null) {
            System.out.println(String.format("IpV4Header decode error, IpV4Packet bytes:[%s]", BytesUtil.byteArrayToHexString(packetBytes, ",")));
            return null;
        }

        byte[] payLoad = new byte[Math.min(length, dataHeader.getTotalLen()) - IpV4Header.BYTE_LENGTH];
        System.arraycopy(packetBytes, offset, payLoad, 0, payLoad.length);

        return new IpV4Packet(dataHeader, payLoad);
    }

}
