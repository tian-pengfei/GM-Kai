package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Logger;


/**
 * Currently only TLCP1.1 is supported
 */
public class GMKaiSSLContextSpi extends SSLContextSpi {

    private static final Logger LOG = Logger.getLogger(SSLContextSpi.class.getName());

    private ContextData contextData;


    private static final ImmutableList<ProtocolVersion> supportedProtocols =
            ImmutableList.of(ProtocolVersion.TLCP11);

    private static final ImmutableList<TLSCipherSuite> supportedCipherSuites =
            ImmutableList.of(TLSCipherSuite.ECC_SM4_CBC_SM3);

    private final ImmutableList<ProtocolVersion> clientDefaultProtocols =
            ImmutableList.of(ProtocolVersion.TLCP11);

    private final ImmutableList<TLSCipherSuite> clientDefaultCipherSuites =
            ImmutableList.of(TLSCipherSuite.ECC_SM4_CBC_SM3);

    private final ImmutableList<ProtocolVersion> serverDefaultProtocols =
            ImmutableList.of(ProtocolVersion.TLCP11);

    private final ImmutableList<TLSCipherSuite> serverDefaultCipherSuites =
            ImmutableList.of(TLSCipherSuite.ECC_SM4_CBC_SM3);


    private final SSLSessionContext clientSessionContext = new GMKaiSSLSessionContext();

    private final SSLSessionContext serverSessionContext = new GMKaiSSLSessionContext();

    private final GMKaiSSLParameters defaultClientSSLParameters = new GMKaiSSLParameters(
            true,
            supportedProtocols,
            supportedCipherSuites,
            serverDefaultProtocols,
            serverDefaultCipherSuites,
            clientDefaultProtocols,
            clientDefaultCipherSuites);

    private final GMKaiSSLParameters defaultServerSSLParameters = new GMKaiSSLParameters(
            false,
            supportedProtocols,
            supportedCipherSuites,
            serverDefaultProtocols,
            serverDefaultCipherSuites,
            clientDefaultProtocols,
            clientDefaultCipherSuites);

    private final TLSCrypto tlsCrypto = new BcTLSCrypto();

    private boolean initialized = false;

    @Override
    protected synchronized void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        this.initialized = false;

        KeyManager keyManager = chooseKeyManager(km);
        X509ExtendedTrustManager trustManager = chooseTrustManager(tm);

        contextData = new ContextData(
                serverSessionContext,
                clientSessionContext,
                keyManager,
                trustManager,
                sr,
                tlsCrypto,
                defaultServerSSLParameters,
                defaultClientSSLParameters);

        this.initialized = true;

    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        checkInitialized();
        return new GMKaiSocketFactory(contextData);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        checkInitialized();
        return new GMKaiServerSocketFactory(contextData);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        //todo
        throw new UnsupportedOperationException("Currently not supported");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        //todo
        throw new UnsupportedOperationException("Currently not supported");
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return serverSessionContext;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }


    private KeyManager chooseKeyManager(KeyManager[] km) {
        if (Objects.isNull(km)) return null;

        return Arrays.stream(km).
                filter(k -> k instanceof TLCPX509KeyManager).
                findFirst().orElse(null);
    }

    private X509ExtendedTrustManager chooseTrustManager(TrustManager[] tm) throws KeyManagementException {
        if (Objects.isNull(tm)) {
            return defaultTrustManager();
        }

        return (X509ExtendedTrustManager) Arrays.
                stream(tm).
                filter(t -> t instanceof X509ExtendedTrustManager).
                findFirst().orElse(defaultTrustManager());
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
        return defaultClientSSLParameters.getSSLParameter();
    }

    private static X509ExtendedTrustManager defaultTrustManager() throws KeyManagementException {
        try {
            GMKaiTLCPX509TrustManagerFactory fact = new GMKaiTLCPX509TrustManagerFactory();
            fact.engineInit((KeyStore) null);
            return (X509ExtendedTrustManager) fact.engineGetTrustManagers()[0];
        } catch (KeyStoreException nsae) {
            throw new KeyManagementException(nsae.toString());
        }
    }

    protected void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("SSLContext has not been initialized.");
        }
    }

}
