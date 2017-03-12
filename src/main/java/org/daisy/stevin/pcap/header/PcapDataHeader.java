package org.daisy.stevin.pcap.header;

import org.daisy.stevin.pcap.util.BytesUtil;

/**
 * pcap数据包头
 *
 * @author stevin.qi
 */
public class PcapDataHeader implements Header {
    /**
     * pcap数据包头总长度
     */
    public static final int BYTE_LENGTH = 16;
    /**
     * 时间戳（秒）：记录数据包抓获的时间 记录方式是从格林尼治时间的1970年1月1日 00:00:00 到抓包时经过的秒数（4个字节）
     */
    private int timeS;
    /**
     * 时间戳（微秒）：抓取数据包时的微秒值（4个字节）
     */
    private int timeMs;
    /**
     * 数据包长度：标识所抓获的数据包保存在 pcap 文件中的实际长度，以字节为单位（4个字节）
     */
    private int caplen;
    /**
     * 数据包实际长度： 所抓获的数据包的真实长度（4个字节） 如果文件中保存不是完整的数据包，那么这个值可能要比前面的数据包长度的值大。
     */
    private int len;

    public int getTimeS() {
        return timeS;
    }

    public void setTimeS(int timeS) {
        this.timeS = timeS;
    }

    public int getTimeMs() {
        return timeMs;
    }

    public void setTimeMs(int timeMs) {
        this.timeMs = timeMs;
    }

    public int getCaplen() {
        return caplen;
    }

    public void setCaplen(int caplen) {
        this.caplen = caplen;
    }

    public int getLen() {
        return len;
    }

    public void setLen(int len) {
        this.len = len;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("PcapDataHeader {timeS=0x");
        builder.append(BytesUtil.intToHexString(timeS));
        builder.append(", timeMs=0x");
        builder.append(BytesUtil.intToHexString(timeMs));
        builder.append(", caplen=");
        builder.append(caplen);
        builder.append(", len=");
        builder.append(len);
        builder.append("}");
        return builder.toString();
    }

    @Override
    public int byteLength() {
        return BYTE_LENGTH;
    }

    public static PcapDataHeader newInstance(byte[] headerBytes, int offset, int length) {
        if (!(BytesUtil.checkValidBytes(headerBytes, offset, length, BYTE_LENGTH))) {
            return null;
        }

        byte[] buff_4 = new byte[4];
        PcapDataHeader dataHeader = new PcapDataHeader();

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int timeS = BytesUtil.byteArrayToInt(buff_4);
        dataHeader.setTimeS(timeS);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        int timeMs = BytesUtil.byteArrayToInt(buff_4);
        dataHeader.setTimeMs(timeMs);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        // 得先逆序再转为 int
        BytesUtil.reverseByteArray(buff_4);
        int caplen = BytesUtil.byteArrayToInt(buff_4);
        dataHeader.setCaplen(caplen);

        System.arraycopy(headerBytes, offset, buff_4, 0, buff_4.length);
        offset += buff_4.length;
        BytesUtil.reverseByteArray(buff_4);
        int len = BytesUtil.byteArrayToInt(buff_4);
        dataHeader.setLen(len);

        return dataHeader;
    }
}
