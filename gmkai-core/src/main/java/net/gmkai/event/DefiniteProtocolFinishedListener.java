package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface DefiniteProtocolFinishedListener extends TLSListener {

    @Subscribe
    void DefiniteProtocol(DefiniteProtocolFinishedEvent event);
}
