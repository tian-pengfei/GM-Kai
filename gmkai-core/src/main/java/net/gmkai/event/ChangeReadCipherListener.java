package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface ChangeReadCipherListener extends TLSListener {

    @Subscribe
    void changeReadCipher(ChangeReadCipherEvent event);
}
