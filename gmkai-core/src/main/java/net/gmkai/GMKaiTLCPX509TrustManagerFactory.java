package net.gmkai;

import com.google.common.collect.Lists;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static net.gmkai.GMKai.JAVA_HOME;
import static net.gmkai.util.PropertyUtils.getSystemProperty;

public class GMKaiTLCPX509TrustManagerFactory extends TrustManagerFactorySpi {

    private static final String JSSE_CA_CERTS_PATH = JAVA_HOME == null ? null : JAVA_HOME
            + "/lib/security/jssecacerts".replace("/", File.separator);

    private static final String CA_CERTS_PATH = JAVA_HOME == null ? null :
            JAVA_HOME + "/lib/security/cacerts".replace("/", File.separator);

    private GMKaiTLCPX509TrustManager current;

    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {

        if (Objects.isNull(ks)) {
            try {
                ks = getDefaultTrustStore();
            } catch (Exception e) {
                throw new KeyStoreException(e.getMessage(), e);
            }
        }
        current = getTrustManager(ks);
    }


    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException
                ("GMKai TLCPX509 TrustManagerFactory does not use "
                        + "ManagerFactoryParameters");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {

        if (Objects.isNull(current)) {
            throw new IllegalStateException("not initialized");
        }
        return new TrustManager[]{current};
    }

    private static KeyStore getDefaultTrustStore() throws Exception {

        String type = Optional.ofNullable(
                getSystemProperty("javax.net.ssl.trustStoreType"))
                .orElse(KeyStore.getDefaultType());

        KeyStore keyStore = KeyStore.getInstance(type);

        String certPath = Lists.newArrayList(
                getSystemProperty("javax.net.ssl.trustStore"),
                JSSE_CA_CERTS_PATH,
                CA_CERTS_PATH).stream().filter(Objects::nonNull).filter(path ->
                new File(path).exists()).findFirst().orElse(null);

        String password = Optional.ofNullable(
                getSystemProperty("javax.net.ssl.trustStore")).orElse(null);

        InputStream inputStream = null;

        if (!Objects.isNull(certPath)) {
            inputStream = new BufferedInputStream(new FileInputStream(certPath));
        }

        keyStore.load(inputStream, Objects.isNull(password) ? null : password.toCharArray());

        return keyStore;
    }

    private static GMKaiTLCPX509TrustManager getTrustManager(KeyStore keyStore) throws KeyStoreException {

        List<X509Certificate> trustedCert = Lists.newArrayList();
        for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements(); ) {
            String alias = en.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    trustedCert.add((X509Certificate) cert);
                }
            }
        }

        return new GMKaiTLCPX509TrustManager(trustedCert);
    }

}

