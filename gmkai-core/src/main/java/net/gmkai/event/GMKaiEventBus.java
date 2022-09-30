package net.gmkai.event;

import com.google.common.eventbus.EventBus;

public class GMKaiEventBus implements TLSEventBus {

    private final EventBus eventBus = new EventBus();


    @Override
    public void postEvent(TLSEvent event) {
        eventBus.post(event);
    }

    @Override
    public void register(TLSListener listener) {
        eventBus.register(listener);
    }

    @Override
    public void unregister(TLSListener listener) {
        eventBus.unregister(listener);
    }
}
