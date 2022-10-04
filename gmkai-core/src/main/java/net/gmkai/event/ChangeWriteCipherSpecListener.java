package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

import java.io.IOException;

public interface ChangeWriteCipherSpecListener extends TLSListener {

    @Subscribe
    void handleChangeWriteCipherSpec() throws IOException;
}
