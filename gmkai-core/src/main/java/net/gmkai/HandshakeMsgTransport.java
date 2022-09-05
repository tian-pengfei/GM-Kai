package net.gmkai;

import java.io.IOException;

interface HandshakeMsgTransport {


    TLSText readHandshakeMsg() throws IOException;

    void writeHandshakeMsg(final byte[] data) throws IOException;
}
