package com.tianpengfei.gmkai.record;

public class SequenceNumber {

    private long value = 0L;

    private boolean exhausted = false;

    synchronized long nextValue() {

        long result = value;
        if (++value == 0) {
            exhausted = true;
        }
        return result;
    }
}
