package org.daisy.stevin.pcap.header;

import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * IP 数据报头
 * 
 * @author stevin.qi
 *
 */
public class IpV4Header implements Header {
    /** IP数据报头字节总长度 */
    public static final int BYTE_LENGTH = 20;

    /**
     * 协议版本号(4 bit)及包头长度(4bit) =（1 字节）
     * 
     * 版本号(Version):一般的值为0100（IPv4），0110（IPv6）
     * 
     * IP包头最小长度为20字节
     */
    private byte varHLen;

    /**
     * Type of Service：服务类型，（1 字节）
     */
    private byte tos;

    /**
     * 总长度（2 字节）
     */
    private int totalLen;

    /**
     * 标识（2 字节）
     */
    private short id;

    /**
     * 标志与偏移量（2 字节）
     */
    private short flagSegment;

    /**
     * Time to Live：生存周期（1 字节）
     */
    private byte ttl;

    /**
     * 协议类型（1 字节）
     */
    private byte protocol;

    /**
     * 头部校验和（2 字节）
     */
    private short checkSum;

    /**
     * 源 IP（4 字节）
     */
    private int srcIP;

    /**
     * 目的 IP（4 字节）
     */
    private int dstIP;

    public byte getVarHLen() {
        return varHLen;
    }

    public void setVarHLen(byte varHLen) {
        this.varHLen = varHLen;
    }

    public byte getTos() {
        return tos;
    }

    public void setTos(byte tos) {
        this.tos = tos;
    }

    public int getTotalLen() {
        return totalLen;
    }

    public void setTotalLen(int totalLen) {
        this.totalLen = totalLen;
    }

    public short getId() {
        return id;
    }

    public void setId(short id) {
        this.id = id;
    }

    public short getFlagSegment() {
        return flagSegment;
    }

    public void setFlagSegment(short flagSegment) {
        this.flagSegment = flagSegment;
    }

    public byte getTtl() {
        return ttl;
    }

    public void setTtl(byte ttl) {
        this.ttl = ttl;
    }

    public byte getProtocol() {
        return protocol;
    }

    public void setProtocol(byte protocol) {
        this.protocol = protocol;
    }

    public short getCheckSum() {
        return checkSum;
    }

    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }

    public int getSrcIP() {
        return srcIP;
    }

    public void setSrcIP(int srcIP) {
        this.srcIP = srcIP;
    }

    public int getDstIP() {
        return dstIP;
    }

    public void setDstIP(int dstIP) {
        this.dstIP = dstIP;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("IPHeader {varHLen=0x");
        builder.append(BytesUtil.byteToHexString(varHLen));
        builder.append(", tos=0x");
        builder.append(BytesUtil.byteToHexString(tos));
        builder.append(", totalLen=");
        builder.append(totalLen);
        builder.append(", id=0x");
        builder.append(BytesUtil.shortToHexString(id));
        builder.append(", flagSegment=0x");
        builder.append(BytesUtil.shortToHexString(flagSegment));
        builder.append(", ttl=");
        builder.append(ttl);
        builder.append(", protocol=");
        builder.append(protocol);
        builder.append(", checkSum=0x");
        builder.append(BytesUtil.shortToHexString(checkSum));
        builder.append(", srcIP=");
        builder.append(BytesUtil.intToIpString(srcIP));
        builder.append(", dstIP=");
        builder.append(BytesUtil.intToIpString(dstIP));
        builder.append("}");
        return builder.toString();
    }

    @Override
    public int byteLength() {
        return BYTE_LENGTH;
    }

    public static IpV4Header newInstance(byte[] headerBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(headerBytes, offset, length, BYTE_LENGTH))) {
            return null;
        }

        IpV4Header ipV4 = new IpV4Header();

        byte[] buff_2 = new byte[2];
        byte[] buff_4 = new byte[4];

        byte varHLen = headerBytes[offset++];
        if (varHLen == 0) {
            return null;
        }
        ipV4.setVarHLen(varHLen);

        byte tos = headerBytes[offset++];
        ipV4.setTos(tos);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        int totalLen = BytesUtil.byteArrayToUnsignedShort(buff_2);
        ipV4.setTotalLen(totalLen);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short id = BytesUtil.byteArrayToShort(buff_2);
        ipV4.setId(id);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short flagSegment = BytesUtil.byteArrayToShort(buff_2);
        ipV4.setFlagSegment(flagSegment);

        byte ttl = headerBytes[offset++];
        ipV4.setTtl(ttl);

        byte protocol = headerBytes[offset++];
        ipV4.setProtocol(protocol);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short checkSum = BytesUtil.byteArrayToShort(buff_2);
        ipV4.setCheckSum(checkSum);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int srcIP = BytesUtil.byteArrayToInt(buff_4);
        ipV4.setSrcIP(srcIP);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int dstIP = BytesUtil.byteArrayToInt(buff_4);
        ipV4.setDstIP(dstIP);

        return ipV4;
    }
}
