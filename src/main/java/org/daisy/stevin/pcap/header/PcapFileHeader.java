package org.daisy.stevin.pcap.header;

import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * pcap文件头
 * 
 * @author stevin.qi
 *
 */
public class PcapFileHeader implements Header {
    /** pacap文件头部字节总长度 */
    public static final int BYTE_LENGTH = 24;
    private int magic; // 标识位，这个标识位的值是16进制的 0xa1b2c3d4（4个字节）
    private short magorVersion; // 主版本号（2个字节）
    private short minorVersion; // 副版本号（2个字节）
    private int timezone; // 区域时间（4个字节）
    private int sigflags; // 精确时间戳（4个字节）
    private int snaplen; // 数据包最大长度（4个字节）
    private int linktype; // 链路层类型（4个字节）

    public PcapFileHeader() {
    }

    public PcapFileHeader(int magic, short magorVersion, short minorVersion, int timezone, int sigflags, int snaplen, int linktype) {
        this.magic = magic;
        this.magorVersion = magorVersion;
        this.minorVersion = minorVersion;
        this.timezone = timezone;
        this.sigflags = sigflags;
        this.snaplen = snaplen;
        this.linktype = linktype;
    }

    public int getMagic() {
        return magic;
    }

    public void setMagic(int magic) {
        this.magic = magic;
    }

    public short getMagorVersion() {
        return magorVersion;
    }

    public void setMagorVersion(short magorVersion) {
        this.magorVersion = magorVersion;
    }

    public short getMinorVersion() {
        return minorVersion;
    }

    public void setMinorVersion(short minorVersion) {
        this.minorVersion = minorVersion;
    }

    public int getTimezone() {
        return timezone;
    }

    public void setTimezone(int timezone) {
        this.timezone = timezone;
    }

    public int getSigflags() {
        return sigflags;
    }

    public void setSigflags(int sigflags) {
        this.sigflags = sigflags;
    }

    public int getSnaplen() {
        return snaplen;
    }

    public void setSnaplen(int snaplen) {
        this.snaplen = snaplen;
    }

    public int getLinktype() {
        return linktype;
    }

    public void setLinktype(int linktype) {
        this.linktype = linktype;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("PcapFileHeader {magic=0x");
        builder.append(BytesUtil.intToHexString(magic));
        builder.append(", magorVersion=0x");
        builder.append(BytesUtil.shortToHexString(magorVersion));
        builder.append(", minorVersion=0x");
        builder.append(BytesUtil.shortToHexString(minorVersion));
        builder.append(", timezone=0x");
        builder.append(BytesUtil.intToHexString(timezone));
        builder.append(", sigflags=0x");
        builder.append(BytesUtil.intToHexString(sigflags));
        builder.append(", snaplen=0x");
        builder.append(BytesUtil.intToHexString(snaplen));
        builder.append(", linktype=0x");
        builder.append(BytesUtil.intToHexString(linktype));
        builder.append("}");
        return builder.toString();
    }

    @Override
    public int byteLength() {
        return BYTE_LENGTH;
    }

    public static PcapFileHeader newInstance(byte[] headerBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(headerBytes, offset, length, BYTE_LENGTH))) {
            return null;
        }

        PcapFileHeader fileHeader = new PcapFileHeader();
        byte[] buff_4 = new byte[4];// 4字节的数组
        byte[] buff_2 = new byte[2]; // 2字节的数组

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int magic = BytesUtil.byteArrayToInt(buff_4);
        fileHeader.setMagic(magic);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short magorVersion = BytesUtil.byteArrayToShort(buff_2);
        fileHeader.setMagorVersion(magorVersion);

        System.arraycopy(headerBytes, offset, buff_2, 0, buff_2.length);
        offset += buff_2.length;
        short minorVersion = BytesUtil.byteArrayToShort(buff_2);
        fileHeader.setMinorVersion(minorVersion);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int timezone = BytesUtil.byteArrayToInt(buff_4);
        fileHeader.setTimezone(timezone);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int sigflags = BytesUtil.byteArrayToInt(buff_4);
        fileHeader.setSigflags(sigflags);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int snaplen = BytesUtil.byteArrayToInt(buff_4);
        fileHeader.setSnaplen(snaplen);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int linktype = BytesUtil.byteArrayToInt(buff_4);
        fileHeader.setLinktype(linktype);

        return fileHeader;
    }

}
