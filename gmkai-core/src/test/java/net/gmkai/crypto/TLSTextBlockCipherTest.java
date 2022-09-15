package net.gmkai.crypto;

import net.gmkai.ContentType;
import net.gmkai.ProtocolVersion;
import net.gmkai.TLSText;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class TLSTextBlockCipherTest {

    private static final TLSCryptoParameters parameters = TLSCryptoParameters.TLSCryptoParametersBuilder.aTLSCryptoParameters()
            .withSelfCryptoKey(Hexs.decode("533aaf2ef3292c54c85ed5cb8ae0d249"))
            .withSelfCryptoKeyIv(Hexs.decode("50d2cf238c7810793342a5013dc82f9a"))
            .withSelfMacKey(Hexs.decode("3e9f03413b91a8adf6519365490079a000d2dd4a052005853adf7fe7041ce13d"))
            .withPeerCryptoKey(Hexs.decode("8c06a8e3e890f677703956904453b386"))
            .withPeerCryptoIv(Hexs.decode("871d2a1206d7a3e6e83fb238f5c95552"))
            .withPeerMackey(Hexs.decode("3be723bff1b758ec8335ea3ff988f43c5a9f194ca12560f9a52e6010f370fb57"))
            .withBulkCipherAlg(BulkCipherAlg.SM4_CBC)
            .withMacAlg(MacAlg.M_SM3)
            .build();


    byte[] sentFragment = Hexs.decode("1400000c6532dca5ea8aadc0351f2776");

    byte[] sentEncryptedFragment = Hexs.decode("f2f24566cce2405f12c507501526a560f6dd4d38dabb384dfa01a99f80c60b94aceaeded97ccae45273a51e4e434a4fbb54b6b2b284d309962169f62caa0d044070e72b00aa9944531fbfb86aa198f17");

    final private TLSText sentEncryptedText = new TLSText(
            ContentType.HANDSHAKE,
            ProtocolVersion.TLCP11,
            sentEncryptedFragment);

    final private TLSText sentPlainText = new TLSText(
            ContentType.HANDSHAKE,
            ProtocolVersion.TLCP11,
            sentFragment);


    byte[] acceptedFragment = Hexs.decode("1400000c636f5868a833c86cc18ff3c0");

    byte[] acceptedEncryptedFragment = Hexs.decode("1ea63b13612f266e533748fda1c425b80e68397f0aa85cba821ce84314b6d140ba76cef683ad6472377a07740033113a0d1cda6145cd3b41bc71b4bf88bdaa05ebc08a76d0ed5b51ba61da52654c38e3");

    final private TLSText acceptedEncryptedText = new TLSText(
            ContentType.HANDSHAKE,
            ProtocolVersion.TLCP11,
            acceptedEncryptedFragment);

    final private TLSText acceptedPlainText = new TLSText(
            ContentType.HANDSHAKE,
            ProtocolVersion.TLCP11,
            acceptedFragment);


    @Test
    public void should_encrypt_TLSText() throws IOException {

        TLSCrypto tlsCrypto = new BcTLSCrypto();

        TLSTextBlockCipher tlsBlockCipher = tlsCrypto.createTLSTextBlockCipher(true, parameters.getWriteTLSTextCryptoParameters());

        TLSText encryptedText = tlsBlockCipher.processTLSText(sentPlainText);


        assertThat(sentEncryptedText.contentType, is(encryptedText.contentType));
        assertThat(sentEncryptedText.fragment, is(encryptedText.fragment));
        assertThat(sentEncryptedText.version, is(encryptedText.version));
    }

    @Test
    public void should_decrypt_TLSText() throws IOException {

        TLSCrypto tlsCrypto = new BcTLSCrypto();

        TLSTextBlockCipher tlsBlockCipher = tlsCrypto.createTLSTextBlockCipher(false, parameters.getReadTLSTextCryptoParameters());

        TLSText _plainText = tlsBlockCipher.processTLSText(acceptedEncryptedText);

        assertThat(acceptedPlainText.contentType, is(_plainText.contentType));
        assertThat(acceptedPlainText.fragment, is(_plainText.fragment));
        assertThat(acceptedPlainText.version, is(_plainText.version));
    }


}
