package org.daisy.stevin.pcap.packet;

public abstract class AbstractPacket implements Packet {
    protected byte[] payload;

    protected AbstractPacket(byte[] payload) {
        this.payload = payload;
    }

    @Override
    public byte[] getPayload() {
        return payload;
    }

}
