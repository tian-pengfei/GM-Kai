package net.gmkai.event;

public interface HandshakeFinishedListener extends TLSListener {

    void handshakeFinished(HandshakeFinishedEvent event);
}

