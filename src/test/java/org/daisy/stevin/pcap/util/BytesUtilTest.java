package org.daisy.stevin.pcap.util;

import org.testng.Assert;
import org.testng.annotations.Test;

public class BytesUtilTest {

    @Test
    public void byteToHexString() {
        byte byteVal = (byte) (254 & 0xFF);
        Assert.assertEquals(BytesUtil.byteToHexString(byteVal).toLowerCase(), "fe");
    }

    @Test
    public void intToHexString() {
        int intVal = 6553543;
        Assert.assertEquals(BytesUtil.intToHexString(intVal).toLowerCase(), "0063ffc7");
    }

    @Test
    public void shortToHexString() {
        short shortVal = (short) (65523 & 0xFFFF);
        Assert.assertEquals(BytesUtil.shortToHexString(shortVal).toLowerCase(), "fff3");
    }
}
