package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface SelfFinishedListener extends TLSListener {

    @Subscribe
    void handleSelfFinished();
}
