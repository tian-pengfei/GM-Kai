package net.gmkai;

import net.gmkai.event.ChangeReadCipherEvent;
import net.gmkai.event.ChangeWriteCipherEvent;
import net.gmkai.event.ChangeWriteCipherSpecEvent;
import net.gmkai.event.GMKaiEventBus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class CipherSpecChangerTest {

    private CipherSpecChanger cipherSpecChanger;

    private GMKaiEventBus tlsEventBus;
    private ChangeCipherSpecTransport changeCipherSpecTransport;

    @BeforeEach
    public void setUp() {

        tlsEventBus = spy(new GMKaiEventBus());

        changeCipherSpecTransport = mock(ChangeCipherSpecTransport.class);

        cipherSpecChanger = new CipherSpecChanger(tlsEventBus, changeCipherSpecTransport);


    }


    @Test
    public void should_handle_unexpected_msg() {

        TLSText tlsText = new TLSText(ContentType.CHANGE_CIPHER_SPEC, ProtocolVersion.TLCP11, new byte[]{0x01});
        cipherSpecChanger.handleMsgFromOtherProtocol(tlsText);
        verify(tlsEventBus).postEvent(isA(ChangeReadCipherEvent.class));
    }

    @Test
    public void should_notify_change_write_cipher() throws IOException {
        tlsEventBus.postEvent(new ChangeWriteCipherSpecEvent());
        verify(tlsEventBus).postEvent(isA(ChangeWriteCipherEvent.class));
        verify(changeCipherSpecTransport).writeChangeCipherSpec();
    }

}
