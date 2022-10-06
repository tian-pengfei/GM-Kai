package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

import java.io.IOException;

public interface ReceivedUnexpectedMsgListener extends TLSListener {


    @Subscribe
    void handleUnexpectMessage(ReceivedUnexpectedMsgEvent event) throws IOException;
}
