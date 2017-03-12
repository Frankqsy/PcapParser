package org.daisy.stevin.pcap.header;


import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * Pcap 捕获的数据帧头：以太网帧，14 个字节
 * 
 * @author stevin.qi
 *
 */
public class EthernetHeader implements Header {
    /** 以太网帧头部字节总长度 */
    public static final int BYTE_LENGTH = 14;

    /** MAC地址字节总长度 */
    private static final int MAC_LENGTH = 6;

    /**
     * 目的 MAC 地址：6 byte
     */
    private byte[] destMac;

    /**
     * 源 MAC 地址：6 byte
     */
    private byte[] srcMac;

    /**
     * 数据帧类型:2 字节
     */
    private short frameType;

    public byte[] getDestMac() {
        return destMac;
    }

    public void setDestMac(byte[] destMac) {
        this.destMac = destMac;
    }

    public byte[] getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(byte[] srcMac) {
        this.srcMac = srcMac;
    }

    public short getFrameType() {
        return frameType;
    }

    public void setFrameType(short frameType) {
        this.frameType = frameType;
    }

    /**
     * 按照 Wireshark 的格式显示信息
     */
    @Override
    public String toString() {
        // frameType 以 十六进制显示
        StringBuilder builder = new StringBuilder();
        builder.append("EthernetHeader {frameType=0x");
        builder.append(BytesUtil.shortToHexString(frameType));
        builder.append(", destMac=");
        builder.append(BytesUtil.byteArrayToHexString(destMac, ":"));
        builder.append(", srcMac=");
        builder.append(BytesUtil.byteArrayToHexString(srcMac, ":"));
        builder.append("}");
        return builder.toString();
    }

    @Override
    public int byteLength() {
        return BYTE_LENGTH;
    }

    public static EthernetHeader newInstance(byte[] headerBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(headerBytes, offset, length, BYTE_LENGTH))) {
            return null;
        }

        EthernetHeader header = new EthernetHeader();

        byte[] destMac = new byte[MAC_LENGTH];
        System.arraycopy(headerBytes, offset, destMac, 0, destMac.length);
        offset += destMac.length;
        header.setDestMac(destMac);

        byte[] srcMac = new byte[MAC_LENGTH];
        System.arraycopy(headerBytes, offset, srcMac, 0, srcMac.length);
        offset += srcMac.length;
        header.setSrcMac(srcMac);

        byte[] buff_2 = new byte[2];
        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        short frameType = BytesUtil.byteArrayToShort(buff_2);
        header.setFrameType(frameType);

        return header;
    }

}
