package net.gmkai;

import java.io.IOException;

public interface ApplicationMsgTransport {

    TLSText readApplicationMsg() throws IOException;

    void writeApplicationMsg(final byte[] data) throws IOException;

}
