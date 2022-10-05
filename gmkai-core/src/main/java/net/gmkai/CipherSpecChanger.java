package net.gmkai;

import net.gmkai.event.*;

import java.io.IOException;
import java.util.Arrays;

public class CipherSpecChanger implements RecordUpperLayerProtocol {

    private final TLSEventBus eventBus;

    private final ChangeCipherSpecTransport changeCipherSpecTransport;

    CipherSpecChanger(TLSEventBus eventBus,
                      ChangeCipherSpecTransport changeCipherSpecTransport) {
        this.eventBus = eventBus;
        this.changeCipherSpecTransport = changeCipherSpecTransport;

        CipherSpecChangerListener cipherSpecChangerListener = new CipherSpecChangerListener();
        eventBus.register(cipherSpecChangerListener);
    }


    private void notifyChangeWriteCipherSpec() throws IOException {
        eventBus.postEvent(new ChangeWriteCipherEvent());
        changeCipherSpecTransport.writeChangeCipherSpec();
    }

    @Override
    public void handleMsgFromOtherProtocol(TLSText tlsText) {
        if (!Arrays.equals(tlsText.fragment, new byte[]{0x01})) {
            throw new RuntimeException("");
        }
        eventBus.postEvent(new ChangeReadCipherEvent());
    }

    private class CipherSpecChangerListener implements ChangeWriteCipherSpecListener {


        @Override
        public void handleChangeWriteCipherSpec(
                ChangeWriteCipherSpecEvent changeWriteCipherSpecEvent) throws IOException {
            notifyChangeWriteCipherSpec();
        }

    }

}
