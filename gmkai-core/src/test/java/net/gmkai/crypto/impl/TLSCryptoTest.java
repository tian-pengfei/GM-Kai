package net.gmkai.crypto.impl;

import net.gmkai.crypto.MacAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSHMac;
import net.gmkai.util.Hexs;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public abstract class TLSCryptoTest {


    private final TLSCrypto tlsCrypto;

    public TLSCryptoTest(TLSCrypto tlsCrypto) {
        this.tlsCrypto = tlsCrypto;
    }

    private final static byte[] src = "Hello GMKai!".getBytes(StandardCharsets.UTF_8);

    private final static byte[] hmac_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    private final static byte[] sm3_hmac = Hexs.decode("bc3cd4c88c1494d9a2c9d84a6dffb05fd8b9ee73eeca249cf3c2f133be55f3d5");

    private final static byte[] sha256_hmac = Hexs.decode("2dc253c580760f202bb7bb210af3d925e80f0acd26225fd234027c1ca6f513f8");

    private static void assertHMac(TLSHMac tlshMac, byte[] macResult) {

        tlshMac.setKey(hmac_key, 0, hmac_key.length);
        tlshMac.update(src, 0, src.length);
        assertThat(tlshMac.calculateMAC(), is(macResult));
    }

    @Test
    public void should_sm3_hmac() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.SM3);
        assertHMac(tlshMac, sm3_hmac);
    }

    @Test
    public void should_sha256_hmac() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.SHA256);
        assertHMac(tlshMac, sha256_hmac);

    }
}
