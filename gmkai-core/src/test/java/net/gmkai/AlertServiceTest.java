package net.gmkai;

import net.gmkai.event.CloseEvent;
import net.gmkai.event.TLSEventBus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLException;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class AlertServiceTest {

    AlertService alertService;

    TLSEventBus tlsEventBus;

    AlertSender alertSender;


    @BeforeEach
    public void setUp() {

        tlsEventBus = mock(TLSEventBus.class);

        alertSender = mock(AlertSender.class);

        alertService = new AlertService(tlsEventBus, alertSender);

    }

    @Test
    public void should_handle_fatal_msg_from_peer() {

        TLSText tlsText = new TLSText(
                ContentType.ALERT,
                ProtocolVersion.TLCP11,
                new AlertMsg(AlertMsg.Level.FATAL, AlertMsg.Description.HANDSHAKE_FAILURE).toBytes());

        Assertions.assertThrows(
                HandledException.class,
                () -> alertService.handleMsgFromOtherProtocol(tlsText));
        verify(tlsEventBus).postEvent(isA(CloseEvent.class));
    }

    @Test
    public void should_handle_warning_msg_from_peer() throws SSLException {

        TLSText tlsText = new TLSText(
                ContentType.ALERT,
                ProtocolVersion.TLCP11,
                new AlertMsg(AlertMsg.Level.WARNING, AlertMsg.Description.NO_RENEGOTIATION).toBytes());
        alertService.handleMsgFromOtherProtocol(tlsText);
    }

    @Test
    public void should_handle_close_notify_msg_from_peer() throws SSLException {

        TLSText tlsText = new TLSText(
                ContentType.ALERT,
                ProtocolVersion.TLCP11,
                new AlertMsg(AlertMsg.Level.WARNING, AlertMsg.Description.CLOSE_NOTIFY).toBytes());

        alertService.handleMsgFromOtherProtocol(tlsText);
        verify(tlsEventBus).postEvent(isA(CloseEvent.class));
    }

    @Test
    public void should_handle_local_fatal_exception() throws IOException {

        AlertMsg alertMsg = new AlertMsg(AlertMsg.Level.FATAL, AlertMsg.Description.DECODE_ERROR);


        Assertions.assertThrows(HandledException.class,
                () -> alertService.handleAlertException(new AlertException(alertMsg)));

        verify(alertSender).sendAlert(alertMsg);

        verify(tlsEventBus).postEvent(isA(CloseEvent.class));
    }

    @Test
    public void should_handle_local_close_notify() throws IOException {

        AlertMsg alertMsg = new AlertMsg(AlertMsg.Level.WARNING, AlertMsg.Description.CLOSE_NOTIFY);

        alertService.handleAlertException(new AlertException(alertMsg));

        verify(alertSender).sendAlert(alertMsg);

        verify(tlsEventBus).postEvent(isA(CloseEvent.class));
    }


    @Test
    public void should_handle_local_warn_exception() throws IOException {

        AlertMsg alertMsg = new AlertMsg(AlertMsg.Level.WARNING,
                AlertMsg.Description.NO_RENEGOTIATION);

        alertService.handleAlertException(new AlertException(alertMsg));

        verify(alertSender).sendAlert(alertMsg);
    }


}
