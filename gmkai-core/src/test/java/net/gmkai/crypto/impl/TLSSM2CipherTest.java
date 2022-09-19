package net.gmkai.crypto.impl;

import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSSM2Cipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public abstract class TLSSM2CipherTest {

    final private byte[] src = "Hello GMKai!".getBytes(StandardCharsets.UTF_8);

    private ECPrivateKey priKey;

    private ECPublicKey pubKey;

    final private TLSCrypto tlsCrypto;

    protected TLSSM2CipherTest(TLSCrypto tlsCrypto) {
        this.tlsCrypto = tlsCrypto;
    }

    @BeforeEach
    public void setup() throws Exception {

        String priKeyFilePath = "src/test/resources/sm2.pri.key.pem";
        priKey = (ECPrivateKey) TestHelper.decodePrivateKey(priKeyFilePath);

        String pubKeyFilePath = "src/test/resources/sm2.pub.key.pem";
        pubKey = (ECPublicKey) TestHelper.decodePublicKey(pubKeyFilePath);

    }

    @Test
    public void should_sm2_encrypt() throws Exception {

        TLSSM2Cipher tlssm2Cipher =
                tlsCrypto.getTLSSM2Cipher(true, pubKey);

        byte[] encryptedText = tlssm2Cipher.processBlock(src, 0, src.length);

        byte[] text = TestHelper.sm2DecryptWithDer(priKey, encryptedText);
        assertThat(text, is(src));

    }

    @Test
    public void should_sm2_decrypt() throws Exception {

        byte[] encryptedText = TestHelper.sm2EncryptWithDer(pubKey, src);

        TLSSM2Cipher tlssm2Cipher =
                tlsCrypto.getTLSSM2Cipher(false, priKey);
        byte[] text = tlssm2Cipher.processBlock(encryptedText, 0, encryptedText.length);

        assertThat(text, is(src));

    }

}
