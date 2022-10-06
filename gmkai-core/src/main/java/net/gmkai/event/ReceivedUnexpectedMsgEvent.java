package net.gmkai.event;

import net.gmkai.TLSText;

public final class ReceivedUnexpectedMsgEvent implements TLSEvent {

    private final TLSText tlsText;

    public ReceivedUnexpectedMsgEvent(TLSText tlsText) {
        this.tlsText = tlsText;
    }

    public TLSText getTlsText() {
        return tlsText;
    }
}
