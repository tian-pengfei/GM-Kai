package net.gmkai;

import javax.net.ssl.SSLException;

public class AlertException extends SSLException {

    private final AlertMsg alertMsg;

    private final boolean isLocal;

    public AlertException(AlertMsg alertMsg, boolean isLocal) {
        super(alertMsg.getDescription().toString());
        this.alertMsg = alertMsg;
        this.isLocal = isLocal;
    }

    public AlertException(AlertMsg alertMsg) {
        this(alertMsg, true);
    }

    public AlertMsg.Level getLevel() {
        return alertMsg.getLevel();
    }

    public AlertMsg.Description getDescription() {
        return alertMsg.getDescription();
    }

    public AlertMsg getAlertMsg() {
        return alertMsg;
    }

    public boolean isLocal() {
        return isLocal;
    }
}
