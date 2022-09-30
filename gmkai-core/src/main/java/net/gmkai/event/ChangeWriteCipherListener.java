package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface ChangeWriteCipherListener extends TLSListener {

    @Subscribe
    void changeWriteCipher(ChangeWriteCipherEvent event);

}
