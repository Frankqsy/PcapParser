package org.daisy.stevin.pcap.handler;

import org.daisy.stevin.pcap.header.PcapDataHeader;
import org.daisy.stevin.pcap.header.PcapFileHeader;
import org.daisy.stevin.pcap.packet.PcapPacket;
import org.daisy.stevin.pcap.util.BytesUtil;
import org.daisy.stevin.pcap.util.NoThrow;

import java.io.FileInputStream;

/**
 * pcap文件处理类
 * 
 * @author stevin.qi
 *
 */
public class PcapHandle {
    private PcapFileHeader fileHeader = null;
    private FileInputStream fis = null;

    public PcapHandle(FileInputStream fis) {
        this.fis = fis;
        this.fileHeader = readFileHeader();
    }

    private PcapFileHeader readFileHeader() {
        if (fis == null) {
            return null;
        }

        PcapFileHeader fileHeader = NoThrow.execute(() -> {
            byte[] fileHeaderBytes = new byte[PcapFileHeader.BYTE_LENGTH];
            int readBytes = fis.read(fileHeaderBytes);
            return PcapFileHeader.newInstance(fileHeaderBytes, 0, readBytes);
        }, (e) -> null);

        return fileHeader;
    }

    public PcapFileHeader getFileHeader() {
        return fileHeader;
    }

    public PcapPacket nextPacket() {
        if (fis == null || fileHeader == null) {
            close();
            return null;
        }

        PcapPacket pcapPkt = NoThrow.execute(() -> {
            byte[] pcapDataHeaderBytes = new byte[PcapDataHeader.BYTE_LENGTH];
            int readBytes = fis.read(pcapDataHeaderBytes);
            if (readBytes < pcapDataHeaderBytes.length) {
                if (readBytes > 0) {
                    String errorMsg = String.format("PcapDataHeader decode error, readBytes:[%d], PcapHeader bytes:[%s]", readBytes,
                            BytesUtil.byteArrayToHexString(pcapDataHeaderBytes, ","));
                    System.out.println(errorMsg);
                }
                return null;
            }
            byte[] buff_4 = new byte[4];
            System.arraycopy(pcapDataHeaderBytes, 8, buff_4, 0, 4);
            BytesUtil.reverseByteArray(buff_4);
            int capLen = BytesUtil.byteArrayToInt(buff_4);
            if (capLen <= 0) {
                return PcapPacket.newPacket(pcapDataHeaderBytes, 0, pcapDataHeaderBytes.length);
            }
            byte[] pcapPktBytes = new byte[pcapDataHeaderBytes.length + capLen];
            System.arraycopy(pcapDataHeaderBytes, 0, pcapPktBytes, 0, pcapDataHeaderBytes.length);
            readBytes = fis.read(pcapPktBytes, pcapDataHeaderBytes.length, capLen);
            if (readBytes < capLen) {
                String errorMsg = String.format("PcapData read error,capLen:[%d],PcapPacket bytes:[%s]", capLen,
                        BytesUtil.byteArrayToHexString(pcapPktBytes, ","));
                System.out.println(errorMsg);
                return null;
            }
            return PcapPacket.newPacket(pcapPktBytes, 0, pcapPktBytes.length);
        }, (e) -> null);

        return pcapPkt;
    }

    public void close() {
        NoThrow.executeNoReturn(() -> {
            if (fis != null) {
                fis.close();
            }
        }, (e) -> {
        });
    }
}
