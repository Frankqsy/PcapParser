package org.daisy.stevin.pcap.header;

import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * UDP 包头：由4个域组成，每个域各占用2个字节
 * 
 * @author stevin.qi
 *
 */
public class UdpHeader implements Header {
    /** UDP数据报头字节总长度 */
    public static final int BYTE_LENGTH = 8;
    private int srcPort; // 源端口(2 字节)
    private int dstPort; // 目的端口(2 字节)
    private int length; // 数据包长，包括首部自身，即最小8(2 字节)
    private short checkSum; // 校验和

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public short getCheckSum() {
        return checkSum;
    }

    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("UdpHeader {srcPort=");
        builder.append(srcPort);
        builder.append(", dstPort=");
        builder.append(dstPort);
        builder.append(", length=");
        builder.append(length);
        builder.append(", checkSum=");
        builder.append(BytesUtil.shortToHexString(checkSum));
        builder.append("}");
        return builder.toString();
    }

    @Override
    public int byteLength() {
        return BYTE_LENGTH;
    }

    public static UdpHeader newInstance(byte[] headerBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(headerBytes, offset, length, BYTE_LENGTH))) {
            return null;
        }

        byte[] buff_2 = new byte[2];
        UdpHeader udp = new UdpHeader();

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int srcPort = BytesUtil.byteArrayToUnsignedShort(buff_2);
        udp.setSrcPort(srcPort);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int dstPort = BytesUtil.byteArrayToUnsignedShort(buff_2);
        udp.setDstPort(dstPort);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int udplength = BytesUtil.byteArrayToUnsignedShort(buff_2);
        udp.setLength(udplength);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short checkSum = BytesUtil.byteArrayToShort(buff_2);
        udp.setCheckSum(checkSum);

        return udp;
    }

}
