package net.gmkai;

import net.gmkai.crypto.BulkCipherAlg;
import net.gmkai.crypto.HashAlg;
import net.gmkai.crypto.KeyExchangeAlg;
import net.gmkai.crypto.MacAlg;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum TLSCipherSuite {

//    NULL("NULL", 0x0000, null, null, null, null),

    ECC_SM4_CBC_SM3("ECC_SM4_CBC_SM3"
            , 0xe013
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchangeAlg.ECC, BulkCipherAlg.SM4_CBC, MacAlg.M_SM3, HashAlg.H_SM3),
    ECDHE_SM4_CBC_SM3("ECDHE_SM4_CBC_SM3"
            , 0xe011
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchangeAlg.ECDHE, BulkCipherAlg.SM4_CBC, MacAlg.M_SM3, HashAlg.H_SM3);


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

    static TLSCipherSuite namesOf(String cipherSuite) {

        return Arrays.stream(values()).filter(c -> c.name.equals(cipherSuite)
        ).findFirst().orElse(null);
    }

    static List<TLSCipherSuite> namesOf(String[] cipherSuites) {

        return Arrays.stream(cipherSuites)
                .map(TLSCipherSuite::valueOf)
                .collect(Collectors.toList());
    }

    public static TLSCipherSuite valueOf(int id) {
        for (TLSCipherSuite cs : TLSCipherSuite.values()) {
            if (cs.id == id) {
                return cs;
            }
        }

        return null;
    }


}
