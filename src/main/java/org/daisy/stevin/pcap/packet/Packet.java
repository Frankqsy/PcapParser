package org.daisy.stevin.pcap.packet;

import org.daisy.stevin.pcap.header.Header;

/**
 * 
 * @author stevin.qi
 *
 */
public interface Packet {
    public Header getHeader();

    public byte[] getPayload();
}
