package com.shaheen.msr.utilities;

import com.shaheen.msr.exception.CustomException;

public class Hex {

    public static byte[] decodeHex(char[] data)
            throws CustomException {
        int len = data.length;

        if ((len & 0x1) != 0) {
            throw new CustomException("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        int i = 0;
        for (int j = 0; j < len; i++) {
            int f = toDigit(data[j], j) << 4;
            j++;
            f |= toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    protected static int toDigit(char ch, int index)
            throws CustomException {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new CustomException("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }
}