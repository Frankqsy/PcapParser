package org.daisy.stevin.pcap.header;

/**
 * 协议数据，五元组
 * 
 * @author stevin.qi
 *
 */
public class Protocol {
    private String srcIP; // 源 IP
    private String desIP; // 目的 IP

    private String srcPort; // 源端口
    private String desPort; // 目的端口

    private ProtocolType protocolType = ProtocolType.OTHER; // 协议类型

    public Protocol() {
    }

    public Protocol(String srcIP, String desIP, String srcPort, String desPort, ProtocolType protocolType) {
        this.srcIP = srcIP;
        this.desIP = desIP;
        this.srcPort = srcPort;
        this.desPort = desPort;
        this.protocolType = protocolType;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public void setSrcIP(String srcIP) {
        this.srcIP = srcIP;
    }

    public String getDesIP() {
        return desIP;
    }

    public void setDesIP(String desIP) {
        this.desIP = desIP;
    }

    public String getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(String srcPort) {
        this.srcPort = srcPort;
    }

    public String getDesPort() {
        return desPort;
    }

    public void setDesPort(String desPort) {
        this.desPort = desPort;
    }

    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Protocol {srcIP=");
        builder.append(srcIP);
        builder.append(", desIP=");
        builder.append(desIP);
        builder.append(", srcPort=");
        builder.append(srcPort);
        builder.append(", desPort=");
        builder.append(desPort);
        builder.append(", protocolType=");
        builder.append(protocolType);
        builder.append("}");
        return builder.toString();
    }
}
