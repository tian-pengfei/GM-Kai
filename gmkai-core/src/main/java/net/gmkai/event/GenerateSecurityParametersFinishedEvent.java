package net.gmkai.event;

import net.gmkai.SecurityParameters;

public final class GenerateSecurityParametersFinishedEvent implements TLSEvent {


    private final SecurityParameters securityParameters;

    public GenerateSecurityParametersFinishedEvent(SecurityParameters securityParameters) {
        this.securityParameters = securityParameters;
    }

    public SecurityParameters getSecurityParameters() {
        return securityParameters;
    }
}
