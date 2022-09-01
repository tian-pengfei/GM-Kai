package net.gmkai.crypto.padding;

import javax.net.ssl.SSLException;
import java.util.Arrays;

public class TLSPadding implements Padding{

    @Override
    public byte[] getPaddingBytes(int dataLen,int blockSize) {

        int code = blockSize-(dataLen+1)%blockSize;
        int count = code+1;
        byte[] buf = new byte[count];

        Arrays.fill(buf, (byte) code);
        return buf;
    }

    @Override
    public int getPaddingCount(byte[] paddedData, int dataOff, int dataLen) throws SSLException {

        int code = paddedData[dataOff+dataLen-1];
        int count = code+1;
        int pos = dataOff+dataLen-count;

        int fail = (code>>31)|((pos-dataOff)>>31);

        for (int i = pos; i <dataOff+dataLen; i++) {
            fail|=(paddedData[i] ^ code);
        }
        if(fail!=0) throw new SSLException("数据损坏，不符合padding规则");

        return count;
    }
}
