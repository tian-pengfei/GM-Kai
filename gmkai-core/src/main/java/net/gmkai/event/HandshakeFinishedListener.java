package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface HandshakeFinishedListener extends TLSListener {

    @Subscribe
    void handshakeFinished(HandshakeFinishedEvent event);
}

