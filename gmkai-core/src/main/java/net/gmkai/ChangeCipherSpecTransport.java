package net.gmkai;

import java.io.IOException;

public interface ChangeCipherSpecTransport {

    void writeChangeCipherSpec() throws IOException;

}
