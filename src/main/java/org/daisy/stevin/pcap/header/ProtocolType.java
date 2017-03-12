package org.daisy.stevin.pcap.header;

/**
 * 协议类型
 * 
 * @author stevin.qi
 *
 */
public enum ProtocolType {
    OTHER("0"), // 其他协议号：默认为0
    TCP("6"), // TCP 协议号：6
    UDP("17"); // UDP 协议号：17

    private String type;

    private ProtocolType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
