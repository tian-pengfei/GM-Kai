package net.gmkai;

import net.gmkai.util.Hexs;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class TLSTextTest {

    private static final TLSText tlsText =
            new TLSText(ContentType.HANDSHAKE, ProtocolVersion.TLCP11, Hexs.decode("010203040506"));

    private static final byte[] tlsTextBytes = Hexs.decode("1601010006010203040506");

    @Test
    public void should_read_TLSText_by_byte_array() throws IOException {

        TLSText _tlsText = TLSText.readTLSText(tlsTextBytes);
        assertThat(tlsText, is(_tlsText));
    }

    @Test
    public void should_read_TLSText_by_input_stream() throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(tlsTextBytes);
        TLSText _tlsText = TLSText.readTLSText(inputStream);
        assertThat(tlsText, is(_tlsText));
    }

    @Test
    public void should_to_bytes() throws IOException {
        assertThat(tlsText.toBytes(), is(tlsTextBytes));
    }
}
