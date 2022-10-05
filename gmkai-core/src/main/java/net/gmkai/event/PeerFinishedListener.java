package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface PeerFinishedListener extends TLSListener {

    @Subscribe
    void handlePeerFinished();
}
