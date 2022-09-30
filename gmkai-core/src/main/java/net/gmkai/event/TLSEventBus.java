package net.gmkai.event;

public interface TLSEventBus {

    void postEvent(TLSEvent event);

    void register(TLSListener listener);

    void unregister(TLSListener listener);

}

