package com.tianpengfei.gmkai;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum CipherSuite {

//    NULL("NULL", 0x0000, null, null, null, null),

    ECC_SM4_CBC_SM3("ECC_SM4_CBC_SM3"
            , 0xe013
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchange.ECC, CipherAlg.SM4_CBC, MacAlg.SM3),
    ECDHE_SM4_CBC_SM3("ECDHE_SM4_CBC_SM3"
            , 0xe011
            , ProtocolVersion.PROTOCOLS_OF_GMSSLs
            , KeyExchange.ECDHE, CipherAlg.SM4_CBC, MacAlg.SM3);


    private final String name;

    private final int id;

    private final ProtocolVersion[] supportedProtocols;

    private final KeyExchange keyExchange;

    private final CipherAlg cipherAlg;

    private final MacAlg macAlg;

    CipherSuite(String name, int id, ProtocolVersion[] supportedProtocols, KeyExchange keyExchange, CipherAlg cipherAlg, MacAlg macAlg) {
        this.name = name;
        this.id = id;
        this.supportedProtocols = supportedProtocols;
        this.keyExchange = keyExchange;
        this.cipherAlg = cipherAlg;
        this.macAlg = macAlg;
    }


    public String getName() {
        return name;
    }

    public int getId() {
        return id;
    }

    public ProtocolVersion[] getSupportedProtocols() {
        return supportedProtocols;
    }

    public KeyExchange getKeyExchange() {
        return keyExchange;
    }

    public CipherAlg getCipherAlg() {
        return cipherAlg;
    }

    public MacAlg getMacAlg() {
        return macAlg;
    }


    static String[] namesOf(List<CipherSuite> cipherSuites) {
        String[] names = new String[cipherSuites.size()];
        int i = 0;
        for (CipherSuite cipherSuite : cipherSuites) {
            names[i++] = cipherSuite.name;
        }

        return names;
    }

    static CipherSuite namesOf(String cipherSuite) {

        return Arrays.stream(values()).filter(c -> c.name.equals(cipherSuite)
        ).findFirst().orElse(null);
    }

    static List<CipherSuite> namesOf(String[] cipherSuites) {

        return Arrays.stream(cipherSuites)
                .map(CipherSuite::valueOf)
                .collect(Collectors.toList());
    }

    public static CipherSuite valueOf(int id) {
        for (CipherSuite cs : CipherSuite.values()) {
            if (cs.id == id) {
                return cs;
            }
        }

        return null;
    }

    enum KeyExchange {

        ECDHE("ECDHE"),
        ECC("ECC"),
        RSA("RSA");

        private final String name;


        KeyExchange(String name) {
            this.name = name;
        }
    }

    enum CipherAlg {
        SM4_CBC("SM4_CBC"),
        SM4_GCM("SM4_CBC");
        private final String name;


        CipherAlg(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    enum MacAlg {
        SM3("SM3"),
        SHA256("SHA256");

        private final String name;


        MacAlg(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

}
