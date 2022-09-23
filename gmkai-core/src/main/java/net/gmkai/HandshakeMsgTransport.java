package net.gmkai;

import java.io.IOException;

interface HandshakeMsgTransport {


    HandshakeMsg readHandshakeMsg() throws IOException;

    void writeHandshakeMsg(HandshakeMsg handshakeMsg) throws IOException;
}
