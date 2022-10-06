package net.gmkai;

import net.gmkai.event.ReceivedUnexpectedMsgEvent;
import net.gmkai.event.ReceivedUnexpectedMsgListener;
import net.gmkai.event.TLSEventBus;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SChannel {

    Handshaker handshaker;

    AlertService alertService;

    private ApplicationDataService applicationDataService;

    private final RecordTransport transport;

    private final InternalContextData internalContextData;

    private final GMKaiSSLParameters gmKaiSSLParameters;

    private final CipherSpecChanger cipherSpecChanger;

    private final TLSEventBus tlsEventBus;

    private final SChannelListener listener;

    SChannel(
            TLSEventBus tlsEventBus,
            InternalContextData internalContextData,
            GMKaiSSLParameters gmKaiSSLParameters,
            PeerInfoProvider peerInfoProvider,
            InputStream inputStream,
            OutputStream outputStream) {

        this.internalContextData = internalContextData;
        this.gmKaiSSLParameters = gmKaiSSLParameters;

        transport = new RecordTransport(tlsEventBus, internalContextData.getTLSCrypto(), inputStream, outputStream);
        this.tlsEventBus = tlsEventBus;
        this.handshaker = new Handshaker(transport, peerInfoProvider, tlsEventBus, internalContextData, gmKaiSSLParameters);
        this.cipherSpecChanger = new CipherSpecChanger(tlsEventBus, transport);
        this.listener = new SChannelListener();
        this.applicationDataService = new ApplicationDataService(tlsEventBus, transport);
        this.alertService = new AlertService(tlsEventBus, transport);
        tlsEventBus.register(listener);

    }

    public synchronized void startHandshake() throws IOException {
        handshaker.startHandshake();
    }

    public InputStream getSInputStream() throws IOException {
        ensureFinishedHandshake();
        return applicationDataService.getAppInputStream();
    }

    public OutputStream getSOutStream() throws IOException {
        ensureFinishedHandshake();
        return applicationDataService.getAppOutStream();
    }

    public SSLSession getHandshakeSession() {
        return handshaker.getHandshakeSession();
    }

    public SSLSession getSession() throws IOException {
        ensureFinishedHandshake();
        return handshaker.getHandshakeSession();
    }

    private void handleUnexpectMessage(TLSText tlsText) throws IOException {
        if (tlsText.contentType == ContentType.HANDSHAKE) {
            handshaker.handleMsgFromOtherProtocol(tlsText);
            return;
        }
        if (tlsText.contentType == ContentType.ALERT) {
            alertService.handleMsgFromOtherProtocol(tlsText);
            return;
        }
        if (tlsText.contentType == ContentType.CHANGE_CIPHER_SPEC) {
            cipherSpecChanger.handleMsgFromOtherProtocol(tlsText);
            return;
        }

        applicationDataService.handleMsgFromOtherProtocol(tlsText);
    }

    private void ensureFinishedHandshake() throws IOException {
        if (handshaker.getFinished()) {
            return;
        }

        startHandshake();
    }


    public void close() {

    }

    private class SChannelListener implements ReceivedUnexpectedMsgListener {

        @Override
        public void handleUnexpectMessage(ReceivedUnexpectedMsgEvent event) throws IOException {
            SChannel.this.handleUnexpectMessage(event.getTlsText());
        }
    }


}
