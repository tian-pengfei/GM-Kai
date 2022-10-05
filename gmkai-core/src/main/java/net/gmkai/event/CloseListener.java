package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface CloseListener extends TLSListener {

    @Subscribe
    void close(CloseEvent closeEvent);
}
