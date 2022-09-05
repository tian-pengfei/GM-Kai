package net.gmkai.crypto.padding;


import net.gmkai.util.Hexs;
import org.junit.Test;

import javax.net.ssl.SSLException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class PaddingTest {


    @Test
    public void should_tls12_padding_bytes() {
        Padding tlsPadding = new TLSPadding();

        byte[] paddingBytes = tlsPadding.getPaddingBytes(12, 8);
        assertThat(paddingBytes, is(Hexs.decode("03030303")));
    }

    @Test
    public void should_tls12_padding_count() throws SSLException {
        Padding tlsPadding = new TLSPadding();
        byte[] paddedData = Hexs.decode("0000000003030303");
        int paddingCount = tlsPadding.getPaddingCount(paddedData, 0, paddedData.length);
        assertThat(paddingCount, is(4));
    }

    @Test(expected = SSLException.class)
    public void should_throw_exception_by_corrupted_data() throws SSLException {
        Padding tlsPadding = new TLSPadding();
        byte[] paddedData = Hexs.decode("0000000002030303");
        int paddingCount = tlsPadding.getPaddingCount(paddedData, 0, paddedData.length);
        assertThat(paddingCount, is(4));
    }
}
