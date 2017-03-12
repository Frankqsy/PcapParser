package org.daisy.stevin.pcap.util;

public class BytesUtil {
    public static int byteArrayToInt(byte[] buff4) {
        int result = buff4[0] & 0xFF;
        result = result << 8 | (buff4[1] & 0xFF);
        result = result << 8 | (buff4[2] & 0xFF);
        result = result << 8 | (buff4[3] & 0xFF);
        return result;
    }

    public static byte[] intToByteArray(int intVal) {
        byte[] result = new byte[4];

        result[0] = (byte) ((intVal & 0xFF000000) >> 24);
        result[1] = (byte) ((intVal & 0x00FF0000) >> 16);
        result[2] = (byte) ((intVal & 0x0000FF00) >> 8);
        result[3] = (byte) (intVal & 0x000000FF);

        return result;
    }

    public static short byteArrayToShort(byte[] buff2) {
        return (short) ((buff2[0] & 0xFF) << 8 | (buff2[1] & 0xFF));
    }

    public static int byteArrayToUnsignedShort(byte[] buff2) {
        return ((buff2[0] & 0xFF) << 8 | (buff2[1] & 0xFF));
    }

    public static byte[] shortToByteArray(short shortVal) {
        byte[] result = new byte[2];

        result[0] = (byte) ((shortVal & 0xFF00) >> 8);
        result[1] = (byte) (shortVal & 0x00FF);

        return result;
    }

    public static void reverseByteArray(byte[] buff4) {
        if (buff4 == null || buff4.length <= 0) {
            return;
        }
        byte temp = 0;
        for (int i = 0; i < buff4.length / 2; i++) {
            temp = buff4[i];
            buff4[i] = buff4[buff4.length - 1 - i];
            buff4[buff4.length - 1 - i] = temp;
        }
    }

    public static String intToHexString(int intVal) {
        return byteArrayToHexString(intToByteArray(intVal), "");
    }

    public static String shortToHexString(short shortVal) {
        return byteArrayToHexString(shortToByteArray(shortVal), "");
    }

    public static String byteToHexString(byte byteVal) {
        String hexStr = Integer.toHexString(byteVal & 0xFF);
        return hexStr != null && hexStr.length() <= 1 ? "0" + hexStr : hexStr;
    }

    public static String byteArrayToHexString(byte[] payload, String split) {
        if (payload == null || payload.length <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < payload.length; i++) {
            sb.append(byteToHexString(payload[i]));
            if (i < payload.length - 1) {
                sb.append(split);
            }
        }

        return sb.toString();
    }

    public static String byteArrayToUTF8Str(byte[] payload) {
        if (payload == null || payload.length <= 0) {
            return "";
        }
        return NoThrow.execute(() -> new String(payload, "UTF-8"), (e) -> byteArrayToHexString(payload, ","));
    }

    public static String byteArrayToIpString(byte[] buff4) {
        if (buff4 == null || buff4.length < 4) {
            return null;
        }

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < buff4.length; i++) {
            builder.append((int) (buff4[i] & 0xff));
            builder.append(".");
        }
        builder.deleteCharAt(builder.length() - 1);

        return builder.toString();
    }

    public static String intToIpString(int ip) {
        return byteArrayToIpString(intToByteArray(ip));
    }

    /**
     * 检查传入的bytes数组是否符合需求
     * 
     * @param packetBytes
     * @param offset
     * @param length
     * @param requiredLen
     *            需要的字节长度
     * @return true 满足需求，false 不满足
     */
    public static boolean checkValidBytes(byte[] packetBytes, int offset, int length, int requiredLen) {
        if (packetBytes == null || offset < 0 || length < 0) {
            return false;
        }
        if (packetBytes.length - offset < length) {
            return false;
        }
        if (length < requiredLen) {
            return false;
        }
        return true;
    }

}
