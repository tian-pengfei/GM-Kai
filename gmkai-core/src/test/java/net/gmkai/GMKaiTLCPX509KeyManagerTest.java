package net.gmkai;

import com.google.common.collect.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class GMKaiTLCPX509KeyManagerTest {

    GMKaiTLCPX509KeyManager gmKaiTLCPX509KeyManager;

    @BeforeEach
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        KeyStore sm2KeyStore = TestHelper.getKeyStore(
                "src/test/resources/sm2.gmkai.pfx",
                "12345678");

        gmKaiTLCPX509KeyManager = new GMKaiTLCPX509KeyManager(sm2KeyStore, "12345678".toCharArray());
    }

    @Test
    public void should_choose_alias() {

        assertThat(gmKaiTLCPX509KeyManager.chooseServerSigAlias("UNKNOWN", null, null),
                is(equalToIgnoringCase("SIG")));

        assertThat(gmKaiTLCPX509KeyManager.chooseServerEncAlias("UNKNOWN", null, null),
                is(equalToIgnoringCase("ENC")));

        assertThat(gmKaiTLCPX509KeyManager.chooseClientSigAlias(new String[]{"UNKNOWN"}, null, null),
                is(equalToIgnoringCase("SIG")));

        assertThat(gmKaiTLCPX509KeyManager.chooseClientEncAlias(new String[]{"UNKNOWN"}, null, null),
                is(equalToIgnoringCase("ENC")));


        assertThat(gmKaiTLCPX509KeyManager.chooseEngineServerSigAlias("UNKNOWN", null, null),
                is(equalToIgnoringCase("SIG")));

        assertThat(gmKaiTLCPX509KeyManager.chooseEngineServerEncAlias("UNKNOWN", null, null),
                is(equalToIgnoringCase("ENC")));

        assertThat(gmKaiTLCPX509KeyManager.chooseEngineClientSigAlias(new String[]{"UNKNOWN"}, null, null),
                is(equalToIgnoringCase("SIG")));

        assertThat(gmKaiTLCPX509KeyManager.chooseEngineClientEncAlias(new String[]{"UNKNOWN"}, null, null),
                is(equalToIgnoringCase("ENC")));
    }


    @Test
    public void should_get_alias() {
        List<String> serverAliases = Lists.newArrayList(
                gmKaiTLCPX509KeyManager.getServerAliases(null, null));
        assertThat(serverAliases, hasSize(2));
        assertThat(serverAliases, contains("Sig", "Enc"));

        List<String> clientAliases = Lists.newArrayList(
                gmKaiTLCPX509KeyManager.getServerAliases(null, null));
        assertThat(clientAliases, hasSize(2));
        assertThat(clientAliases, contains("Sig", "Enc"));
    }


    @Test
    public void should_get_cert_chain() {
        X509Certificate[] chain = gmKaiTLCPX509KeyManager.getCertificateChain("sig", "enc");
        assertThat(chain, notNullValue());
        assertThat(chain.length, greaterThanOrEqualTo(2));
        assertThat(gmKaiTLCPX509KeyManager.getCertificateChain("sig1", "enc"), nullValue());

    }

    @Test
    public void should_get_private_key() {

        assertThat(gmKaiTLCPX509KeyManager.getPrivateKey("ENC"), notNullValue());
        assertThat(gmKaiTLCPX509KeyManager.getPrivateKey("ENC1"), nullValue());
    }


}
