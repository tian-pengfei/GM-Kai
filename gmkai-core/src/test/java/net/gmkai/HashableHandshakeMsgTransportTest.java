package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.crypto.HashAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HashableHandshakeMsgTransportTest {

    List<String> datas = ImmutableList.of(
            "0100002b01016ed2061ae7b0511044e203960f3ed0eed93e298a5c575e56489f382991414163000004e013e0110100",
            "02000026010163296bf611a7ef5dbb1579df434f8d4b1e7480e31a273854e4ba9dc25004f07500e01300",
            "0b0005ae0005ab0002d3308202cf30820272a00302010202051336393370300c06082a811ccf5501837505003025310b300906035504061302434e31163014060355040a0c0d4346434120534d32204f434131301e170d3231303631313039303532305a170d3236303631393038313635365a308191310b300906035504061302434e310f300d06035504080c06e58c97e4baac310f300d06035504070c06e58c97e4baac31273025060355040a0c1ee4b8ade59bbde993b6e8a18ce882a1e4bbbde69c89e99990e585ace58fb83111300f060355040b0c084c6f63616c205241310c300a060355040b0c0353534c3116301406035504030c0d6562737365632e626f632e636e3059301306072a8648ce3d020106082a811ccf5501822d03420004fb0d527a1940cf424a7bc2e7b4dbbdd7f23930ae3ce4a56663c0cb104a163f98d501ffc65b9b1dd55fe57a87aced63083462eda37920a197405d78f7673cd373a382011e3082011a301f0603551d230418301680145c9358205a247356101b645010ece9a7ca074111300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e636663612e636f6d2e636e2f534d322f63726c353631382e63726c30180603551d110411300f820d6562737365632e626f632e636e300e0603551d0f0101ff0404030206c0301d0603551d0e041604149ea8168fceaca80384714e4696aad38917ed3d4a301d0603551d250416301406082b0601050507030206082b06010505070301300c06082a811ccf5501837505000349003046022100af852bdbbf987a11197561c08b83e7f3f5495e41b68f7c1630523503d9d00755022100c442e24f52fe6482d14a54bc2aa1fc3402d948bc4dc71de46d888184ac72750d0002d2308202ce30820272a00302010202051336393371300c06082a811ccf5501837505003025310b300906035504061302434e31163014060355040a0c0d4346434120534d32204f434131301e170d3231303631313039303532305a170d3236303631393038313635365a308191310b300906035504061302434e310f300d06035504080c06e58c97e4baac310f300d06035504070c06e58c97e4baac31273025060355040a0c1ee4b8ade59bbde993b6e8a18ce882a1e4bbbde69c89e99990e585ace58fb83111300f060355040b0c084c6f63616c205241310c300a060355040b0c0353534c3116301406035504030c0d6562737365632e626f632e636e3059301306072a8648ce3d020106082a811ccf5501822d03420004c9f5abe85b5748b5aa7280cbb41e67765f003fa0a875f817932a221b1aace0e55ac6af7ff75ca6b0b4176efbcdce38698041ff7b9ccb83c5a976911d0a7c3c4ca382011e3082011a301f0603551d230418301680145c9358205a247356101b645010ece9a7ca074111300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e636663612e636f6d2e636e2f534d322f63726c353631382e63726c30180603551d110411300f820d6562737365632e626f632e636e300e0603551d0f0101ff040403020338301d0603551d0e041604145fdad491efccbcdba456c19635fb84dc51a63ff6301d0603551d250416301406082b0601050507030206082b06010505070301300c06082a811ccf5501837505000348003045022100c23858b579972088deadfa1ea5c4bc1282b021dc96a597e67203678fc3ac5c8f02203720efa3beb5769c0985cc967f25420276937f455fe032d62352be4bba6852bf",
            "0c00004a00483046022100ce9e568bb4719f681b7dedcba20f6ccb88eba0eac3e5ff673edecb694d89843b0221008a61fe7ca6946713ec236aa453b72398d3e7d8723110b70edba2f14d203b0b51",
            "0e000000",
            "1000009d009b30819802205fbefaabe08b0ced28dda16b0fdb3a526ef41ad354f8e6ad93b61488fe49767b022074cd20134a865062b63b754485fec4cd46f1dcf115a4ddb88df78d1f6236ac6c04209731dbaec2e924bbd6ebd496739e432b57d2f93341b9a29fa1e5f5a3a72bfdf304306074b6fca87562008af94341107a7ba2ec588b39d4e3ad50103088654de1f4f3d8cee1280f49f3bd057c5573eba4ecb9"
    );


    private static final byte[] addedClientFinishedData = Hexs.decode("1400000c865de39c6499a9fcdda472fa");

    private static final byte[] clientHash = Hexs.decode("9bc198123f018c7519a817e64f25b86709146b827ff4c5313d77f0ec0827f640");

    private static final byte[] serverHash = Hexs.decode("8ee5daac569d081be9d3c74b7a4c765703dbaadee25aefd618775548a5c495c7");

    private static final byte[] nullHash = Hexs.decode("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B");

    private HashableHandshakeMsgTransport hashableHandshakeMsgTransport;

    @BeforeEach
    private void setUp() throws IOException {


        HandshakeMsgTransport handshakeMsgTransport = mock(HandshakeMsgTransport.class);
        when(handshakeMsgTransport.readHandshakeMsg()).
                thenReturn(HandshakeMsg.getInstance(addedClientFinishedData));

        hashableHandshakeMsgTransport = new HashableHandshakeMsgTransport(handshakeMsgTransport);

        for (String data : datas) {
            hashableHandshakeMsgTransport.writeHandshakeMsg(HandshakeMsg.getInstance(Hexs.decode(data)));
        }

        TLSCrypto tlsCrypto = new BcTLSCrypto();

        hashableHandshakeMsgTransport.init(tlsCrypto.createHash(HashAlg.H_SM3));
    }

    @Test
    public void should_get_current_hash() {
        byte[] expectedHash = hashableHandshakeMsgTransport.getCurrentHash();
        assertThat(expectedHash, is(clientHash));
    }

    @Test
    public void should_get_hash_after_write_data() throws IOException {
        hashableHandshakeMsgTransport.writeHandshakeMsg(HandshakeMsg.getInstance(addedClientFinishedData));
        byte[] actualPreHash = hashableHandshakeMsgTransport.getPreHash();
        byte[] actualCurrentHash = hashableHandshakeMsgTransport.getCurrentHash();
        assertThat(actualPreHash, is(clientHash));
        assertThat(actualCurrentHash, is(serverHash));
    }

    @Test
    public void should_get_hash_after_read_data() throws IOException {
        hashableHandshakeMsgTransport.readHandshakeMsg();
        byte[] actualPreHash = hashableHandshakeMsgTransport.getPreHash();
        byte[] actualCurrentHash = hashableHandshakeMsgTransport.getCurrentHash();
        assertThat(actualPreHash, is(clientHash));
        assertThat(actualCurrentHash, is(serverHash));
    }

    @Test
    public void should_reset() {
        hashableHandshakeMsgTransport.reset();
        byte[] expectedCurrentHash = hashableHandshakeMsgTransport.getCurrentHash();
        assertThat(expectedCurrentHash, is(nullHash));
    }

    @Test
    public void should_throw_exception_get_pre_hash_after_reset() {
        hashableHandshakeMsgTransport.reset();
        Assertions.assertThrowsExactly(RuntimeException.class,
                () -> hashableHandshakeMsgTransport.getPreHash());
    }


}
