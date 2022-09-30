package net.gmkai.event;

import net.gmkai.NegotiationResult;
import net.gmkai.ProtocolVersion;

public final class DefiniteProtocolFinishedEvent implements TLSEvent {

    private final NegotiationResult negotiationResult;

    public DefiniteProtocolFinishedEvent(NegotiationResult negotiationResult) {
        this.negotiationResult = negotiationResult;
    }

    public ProtocolVersion getProtocol() {
        return negotiationResult.version;
    }
}
