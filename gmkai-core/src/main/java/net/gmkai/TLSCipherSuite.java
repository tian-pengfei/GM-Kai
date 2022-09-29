package net.gmkai;

import net.gmkai.crypto.BulkCipherAlg;
import net.gmkai.crypto.HashAlg;
import net.gmkai.crypto.KeyExchangeAlg;
import net.gmkai.crypto.MacAlg;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public enum TLSCipherSuite {

//    NULL("NULL", 0x0000, null, null, null, null),

    ECC_SM4_CBC_SM3("ECC_SM4_CBC_SM3"
            , 0xe013
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchangeAlg.K_ECC, BulkCipherAlg.SM4_CBC, MacAlg.M_SM3, HashAlg.H_SM3),

    ECDHE_SM4_CBC_SM3("ECDHE_SM4_CBC_SM3"
            , 0xe011
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchangeAlg.K_ECDHE, BulkCipherAlg.SM4_CBC, MacAlg.M_SM3, HashAlg.H_SM3),

    RSA_SM4_CBC_SHA256("RSA_SM4_CBC_SHA256"
            , 0xe01c
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchangeAlg.K_RSA, BulkCipherAlg.SM4_CBC, MacAlg.M_SHA256, HashAlg.H_SM3);


    public final String name;

    public final int id;

    public final ProtocolVersion[] supportedProtocols;

    public final KeyExchangeAlg keyExchangeAlg;

    public final BulkCipherAlg bulkCipherAlg;

    public final MacAlg macAlg;

    public final HashAlg hashAlg;

    TLSCipherSuite(String name, int id, ProtocolVersion[] supportedProtocols, KeyExchangeAlg keyExchangeAlg, BulkCipherAlg bulkCipherAlg, MacAlg macAlg, HashAlg hashAlg) {
        this.name = name;
        this.id = id;
        this.supportedProtocols = supportedProtocols;
        this.keyExchangeAlg = keyExchangeAlg;
        this.bulkCipherAlg = bulkCipherAlg;
        this.macAlg = macAlg;
        this.hashAlg = hashAlg;
    }


    static String[] namesOf(List<TLSCipherSuite> cipherSuites) {
        String[] names = new String[cipherSuites.size()];
        int i = 0;
        for (TLSCipherSuite cipherSuite : cipherSuites) {
            names[i++] = cipherSuite.name;
        }

        return names;
    }

    static Optional<TLSCipherSuite> namesOf(String cipherSuite) {

        return Arrays.stream(values()).filter(c -> c.name.equals(cipherSuite)
        ).findFirst();
    }

    static List<TLSCipherSuite> namesOf(String[] cipherSuites) {

        return Arrays.stream(cipherSuites)
                .map(TLSCipherSuite::valueOf)
                .collect(Collectors.toList());
    }

    public static Optional<TLSCipherSuite> valueOf(int id) {

        return Arrays.stream(TLSCipherSuite.values()).
                filter(cs -> cs.id == id).
                findFirst();
    }


}
