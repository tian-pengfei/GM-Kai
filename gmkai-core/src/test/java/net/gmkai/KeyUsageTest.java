package net.gmkai;

import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static net.gmkai.KeyUsage.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class KeyUsageTest {


    @Test
    public void should_create() throws CertificateException, NoSuchProviderException, IOException {
        new KeyUsage(1);
        X509Certificate certificate = TestHelper.
                getX509CertificateFromPEM("src/test/resources/sm2.oca.pem");
        new KeyUsage(certificate);

    }

    @Test
    public void should_verify_with_unsatisfied_situation() {
        KeyUsage keyUsage = new KeyUsage(1);
        assertThat(keyUsage.verify(keyEncipherment), is(false));
    }

    @Test
    public void should_verify_with_satisfied_situation() {
        KeyUsage keyUsage = new KeyUsage(1);
        assertThat(keyUsage.verify(KeyUsage.decipherOnly), is(true));
    }

    @Test
    public void should_add() {
        KeyUsage keyUsage = new KeyUsage(0).
                add(digitalSignature).add(nonRepudiation).add(keyEncipherment).
                add(dataEncipherment).add(keyAgreement).add(keyCertSign).
                add(cRLSign).add(encipherOnly).add(decipherOnly);
        assertThat(keyUsage, is(equalTo(new KeyUsage((1 << 9) - 1))));
    }
}
