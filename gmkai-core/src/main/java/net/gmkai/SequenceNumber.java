package net.gmkai;

public class SequenceNumber {

    private long value = 0L;

    private boolean exhausted = false;

    public synchronized long nextValue() {

        long result = value;
        if (++value == 0) {
            exhausted = true;
        }
        return result;
    }

    synchronized void init() {
        value = 0;
    }
}
