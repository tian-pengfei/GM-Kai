package net.gmkai;

import net.gmkai.util.Certificates;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


public class CertificateNodeTest {

    HandshakeContext handshakeContext;

    byte[] certificateMessage;

    X509Certificate[] chain;

    @BeforeEach
    public void setUp() throws SSLException {
        this.handshakeContext = mock(HandshakeContext.class);

        this.chain = new X509Certificate[]{Certificates.encodedCert2x509Certificate(Hexs.decode("308202cf30820272a00302010202051336393370300c06082a811ccf5501837505003025310b300906035504061302434e31163014060355040a0c0d4346434120534d32204f434131301e170d3231303631313039303532305a170d3236303631393038313635365a308191310b300906035504061302434e310f300d06035504080c06e58c97e4baac310f300d06035504070c06e58c97e4baac31273025060355040a0c1ee4b8ade59bbde993b6e8a18ce882a1e4bbbde69c89e99990e585ace58fb83111300f060355040b0c084c6f63616c205241310c300a060355040b0c0353534c3116301406035504030c0d6562737365632e626f632e636e3059301306072a8648ce3d020106082a811ccf5501822d03420004fb0d527a1940cf424a7bc2e7b4dbbdd7f23930ae3ce4a56663c0cb104a163f98d501ffc65b9b1dd55fe57a87aced63083462eda37920a197405d78f7673cd373a382011e3082011a301f0603551d230418301680145c9358205a247356101b645010ece9a7ca074111300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e636663612e636f6d2e636e2f534d322f63726c353631382e63726c30180603551d110411300f820d6562737365632e626f632e636e300e0603551d0f0101ff0404030206c0301d0603551d0e041604149ea8168fceaca80384714e4696aad38917ed3d4a301d0603551d250416301406082b0601050507030206082b06010505070301300c06082a811ccf5501837505000349003046022100af852bdbbf987a11197561c08b83e7f3f5495e41b68f7c1630523503d9d00755022100c442e24f52fe6482d14a54bc2aa1fc3402d948bc4dc71de46d888184ac72750d")),
                Certificates.encodedCert2x509Certificate(Hexs.decode("308202ce30820272a00302010202051336393371300c06082a811ccf5501837505003025310b300906035504061302434e31163014060355040a0c0d4346434120534d32204f434131301e170d3231303631313039303532305a170d3236303631393038313635365a308191310b300906035504061302434e310f300d06035504080c06e58c97e4baac310f300d06035504070c06e58c97e4baac31273025060355040a0c1ee4b8ade59bbde993b6e8a18ce882a1e4bbbde69c89e99990e585ace58fb83111300f060355040b0c084c6f63616c205241310c300a060355040b0c0353534c3116301406035504030c0d6562737365632e626f632e636e3059301306072a8648ce3d020106082a811ccf5501822d03420004c9f5abe85b5748b5aa7280cbb41e67765f003fa0a875f817932a221b1aace0e55ac6af7ff75ca6b0b4176efbcdce38698041ff7b9ccb83c5a976911d0a7c3c4ca382011e3082011a301f0603551d230418301680145c9358205a247356101b645010ece9a7ca074111300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e636663612e636f6d2e636e2f534d322f63726c353631382e63726c30180603551d110411300f820d6562737365632e626f632e636e300e0603551d0f0101ff040403020338301d0603551d0e041604145fdad491efccbcdba456c19635fb84dc51a63ff6301d0603551d250416301406082b0601050507030206082b06010505070301300c06082a811ccf5501837505000348003045022100c23858b579972088deadfa1ea5c4bc1282b021dc96a597e67203678fc3ac5c8f02203720efa3beb5769c0985cc967f25420276937f455fe032d62352be4bba6852bf"))};

        this.certificateMessage = Hexs.decode("0005ab0002d3308202cf30820272a00302010202051336393370300c06082a811ccf5501837505003025310b300906035504061302434e31163014060355040a0c0d4346434120534d32204f434131301e170d3231303631313039303532305a170d3236303631393038313635365a308191310b300906035504061302434e310f300d06035504080c06e58c97e4baac310f300d06035504070c06e58c97e4baac31273025060355040a0c1ee4b8ade59bbde993b6e8a18ce882a1e4bbbde69c89e99990e585ace58fb83111300f060355040b0c084c6f63616c205241310c300a060355040b0c0353534c3116301406035504030c0d6562737365632e626f632e636e3059301306072a8648ce3d020106082a811ccf5501822d03420004fb0d527a1940cf424a7bc2e7b4dbbdd7f23930ae3ce4a56663c0cb104a163f98d501ffc65b9b1dd55fe57a87aced63083462eda37920a197405d78f7673cd373a382011e3082011a301f0603551d230418301680145c9358205a247356101b645010ece9a7ca074111300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e636663612e636f6d2e636e2f534d322f63726c353631382e63726c30180603551d110411300f820d6562737365632e626f632e636e300e0603551d0f0101ff0404030206c0301d0603551d0e041604149ea8168fceaca80384714e4696aad38917ed3d4a301d0603551d250416301406082b0601050507030206082b06010505070301300c06082a811ccf5501837505000349003046022100af852bdbbf987a11197561c08b83e7f3f5495e41b68f7c1630523503d9d00755022100c442e24f52fe6482d14a54bc2aa1fc3402d948bc4dc71de46d888184ac72750d0002d2308202ce30820272a00302010202051336393371300c06082a811ccf5501837505003025310b300906035504061302434e31163014060355040a0c0d4346434120534d32204f434131301e170d3231303631313039303532305a170d3236303631393038313635365a308191310b300906035504061302434e310f300d06035504080c06e58c97e4baac310f300d06035504070c06e58c97e4baac31273025060355040a0c1ee4b8ade59bbde993b6e8a18ce882a1e4bbbde69c89e99990e585ace58fb83111300f060355040b0c084c6f63616c205241310c300a060355040b0c0353534c3116301406035504030c0d6562737365632e626f632e636e3059301306072a8648ce3d020106082a811ccf5501822d03420004c9f5abe85b5748b5aa7280cbb41e67765f003fa0a875f817932a221b1aace0e55ac6af7ff75ca6b0b4176efbcdce38698041ff7b9ccb83c5a976911d0a7c3c4ca382011e3082011a301f0603551d230418301680145c9358205a247356101b645010ece9a7ca074111300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e636663612e636f6d2e636e2f534d322f63726c353631382e63726c30180603551d110411300f820d6562737365632e626f632e636e300e0603551d0f0101ff040403020338301d0603551d0e041604145fdad491efccbcdba456c19635fb84dc51a63ff6301d0603551d250416301406082b0601050507030206082b06010505070301300c06082a811ccf5501837505000348003045022100c23858b579972088deadfa1ea5c4bc1282b021dc96a597e67203678fc3ac5c8f02203720efa3beb5769c0985cc967f25420276937f455fe032d62352be4bba6852bf");
        when(handshakeContext.getCurrentCipherSuite()).thenReturn(TLSCipherSuite.ECC_SM4_CBC_SM3);

    }

    @Test
    public void should_server_product_certificate_message() throws IOException {

        CertificateNode certificateNode =
                new CertificateNode(handshakeContext -> false, handshakeContext -> false);
        InternalTLCPX509KeyManager internalTLCPX509KeyManager = mock(InternalTLCPX509KeyManager.class);
        when(internalTLCPX509KeyManager.getCertificateChain(any(), any())).thenReturn(chain);
        when(handshakeContext.getKeyManager()).thenReturn(internalTLCPX509KeyManager);

        HandshakeMsg handshakeMsg = certificateNode.doProduce(handshakeContext);

        verify(handshakeContext).setLocalCertChain(chain);
        assertThat(handshakeMsg.getBody(), is(certificateMessage));
    }

    @Test
    public void should_client_consume_certificate_message() throws IOException {

        CertificateNode certificateNode =
                new CertificateNode(handshakeContext -> false, handshakeContext -> false);

        when(handshakeContext.isClientMode()).thenReturn(true);
        when(handshakeContext.getX509TrustManager()).thenReturn(mock(InternalX509TrustManager.class));

        certificateNode.doConsume(handshakeContext, certificateMessage);

        verify(handshakeContext).setPeerCertChain(chain);

    }


}
