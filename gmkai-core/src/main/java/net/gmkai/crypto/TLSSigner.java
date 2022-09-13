package net.gmkai.crypto;

import java.io.IOException;

public interface TLSSigner {

    void addData(byte[]... data);

    byte[] getSignature() throws IOException;
}
