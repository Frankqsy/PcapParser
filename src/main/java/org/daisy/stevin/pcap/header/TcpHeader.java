package org.daisy.stevin.pcap.header;

import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * TCP 包头：20 字节
 * 
 * @author stevin.qi
 *
 */
public class TcpHeader implements Header {
    /** TCP数据报头字节总长度 */
    public static final int BYTE_LENGTH = 20;

    /**
     * 源端口（2 字节）
     */
    private int srcPort;

    /**
     * 目的端口（2 字节）
     */
    private int dstPort;

    /**
     * Sequence Number：发送数据包中的第一个字节的序列号（4 字节）
     */
    private int seqNum;

    /**
     * 确认序列号（4 字节）
     */
    private int ackNum;

    /**
     * 数据报头的长度(4 bit) + 保留(4 bit) = 1 byte,使用short保存是为了获取报头长度，保证不为负
     */
    private short headerLen;

    /**
     * 标识TCP不同的控制消息(1 字节)
     */
    private byte flags;

    /**
     * 接收缓冲区的空闲空间，用来告诉TCP连接对端自己能够接收的最大数据长度（2 字节）
     */
    private int window;

    /**
     * 校验和（2 字节）
     */
    private short checkSum;

    /**
     * 紧急指针（2 字节）
     */
    private int urgentPointer;

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

    public int getSeqNum() {
        return seqNum;
    }

    public void setSeqNum(int seqNum) {
        this.seqNum = seqNum;
    }

    public int getAckNum() {
        return ackNum;
    }

    public void setAckNum(int ackNum) {
        this.ackNum = ackNum;
    }

    public short getHeaderLen() {
        return headerLen;
    }

    public void setHeaderLen(short headerLen) {
        this.headerLen = headerLen;
    }

    public byte getFlags() {
        return flags;
    }

    public void setFlags(byte flags) {
        this.flags = flags;
    }

    public int getWindow() {
        return window;
    }

    public void setWindow(int window) {
        this.window = window;
    }

    public short getCheckSum() {
        return checkSum;
    }

    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }

    public int getUrgentPointer() {
        return urgentPointer;
    }

    public void setUrgentPointer(int urgentPointer) {
        this.urgentPointer = urgentPointer;
    }

    /**
     * 获取tcp包真正的首部长度，包括可选项在内
     * 
     * @return
     */
    public int realHeadLength() {
        return (this.headerLen >> 4) * 4;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("TcpHeader {srcPort=");
        builder.append(srcPort);
        builder.append(", dstPort=");
        builder.append(dstPort);
        builder.append(", seqNum=0x");
        builder.append(BytesUtil.intToHexString(seqNum));
        builder.append(", ackNum=0x");
        builder.append(BytesUtil.intToHexString(ackNum));
        builder.append(", headerLen=0x");
        builder.append(BytesUtil.byteToHexString((byte) headerLen));
        builder.append(", flags=0x");
        builder.append(BytesUtil.byteToHexString(flags));
        builder.append(", window=");
        builder.append(window);
        builder.append(", checkSum=0x");
        builder.append(BytesUtil.shortToHexString(checkSum));
        builder.append(", urgentPointer=");
        builder.append(urgentPointer);
        builder.append("}");
        return builder.toString();
    }

    @Override
    public int byteLength() {
        return BYTE_LENGTH;
    }

    public static TcpHeader newInstance(byte[] headerBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(headerBytes, offset, length, BYTE_LENGTH))) {
            return null;
        }

        byte[] buff_2 = new byte[2];
        byte[] buff_4 = new byte[4];
        TcpHeader tcp = new TcpHeader();

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int srcPort = BytesUtil.byteArrayToUnsignedShort(buff_2);
        tcp.setSrcPort(srcPort);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int dstPort = BytesUtil.byteArrayToUnsignedShort(buff_2);
        tcp.setDstPort(dstPort);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int seqNum = BytesUtil.byteArrayToInt(buff_4);
        tcp.setSeqNum(seqNum);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int ackNum = BytesUtil.byteArrayToInt(buff_4);
        tcp.setAckNum(ackNum);

        buff_2[0] = 0;
        buff_2[1] = headerBytes[offset++];
        short headerLen = BytesUtil.byteArrayToShort(buff_2);
        tcp.setHeaderLen(headerLen);

        byte flags = headerBytes[offset++];
        tcp.setFlags(flags);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int window = BytesUtil.byteArrayToUnsignedShort(buff_2);
        tcp.setWindow(window);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short checkSum = BytesUtil.byteArrayToShort(buff_2);
        tcp.setCheckSum(checkSum);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int urgentPointer = BytesUtil.byteArrayToUnsignedShort(buff_2);
        tcp.setUrgentPointer(urgentPointer);

        return tcp;
    }
}
