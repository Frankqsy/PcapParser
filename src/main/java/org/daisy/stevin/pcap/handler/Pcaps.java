package org.daisy.stevin.pcap.handler;

import org.daisy.stevin.pcap.util.NoThrow;
import org.daisy.stevin.pcap.util.StringUtil;

import java.io.FileInputStream;

public class Pcaps {
    public static PcapHandle openOfflineFile(String filePath) {
        if (StringUtil.isEmpty(filePath)) {
            return null;
        }
        
        PcapHandle handle = NoThrow.execute(() -> {
            FileInputStream fis = new FileInputStream(filePath);
            return new PcapHandle(fis);
        }, (e) -> null);

        return handle;
    }
}
