package net.gmkai;

import net.gmkai.event.CloseEvent;
import net.gmkai.event.TLSEventBus;

import javax.net.ssl.SSLException;
import java.util.logging.Level;
import java.util.logging.Logger;

class AlertService implements RecordUpperLayerProtocol {

    private final AlertSender alertSender;

    private final TLSEventBus tlsEventBus;

    private static final Logger LOG = Logger.getLogger(AlertService.class.getName());

    public AlertService(TLSEventBus tlsEventBus, AlertSender alertSender) {
        this.alertSender = alertSender;
        this.tlsEventBus = tlsEventBus;
    }

    @Override
    public void handleMsgFromOtherProtocol(TLSText tlsText) throws SSLException {
        AlertMsg alertMsg = AlertMsg.getInstance(tlsText.fragment);
        AlertException alertException = new AlertException(alertMsg, false);
        handleAlertException(alertException);
    }

    public void handleAlertException(AlertException alertException) throws SSLException {

        LOG.log(Level.FINE, String.format("%s alert,level:%s," +
                        "description:%s",
                alertException.isLocal() ? "send" : "rev",
                alertException.getLevel(),
                alertException.getDescription()));


        if (alertException.isLocal()) {
            try {
                alertSender.sendAlert(alertException.getAlertMsg());
            } catch (Exception e) {
                throw new SSLException(e.getMessage(), e);
            }
        }

        if (alertException.getDescription() != AlertMsg.Description.CLOSE_NOTIFY
                && alertException.getLevel() == AlertMsg.Level.WARNING) {
            return;
        }

        tlsEventBus.postEvent(new CloseEvent());
        if (alertException.getLevel() == AlertMsg.Level.FATAL) {
            throw new HandledException(alertException);
        }
    }

}
