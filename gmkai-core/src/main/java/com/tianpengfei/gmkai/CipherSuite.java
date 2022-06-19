package com.tianpengfei.gmkai;

public enum CipherSuite {


    ECDHE_SM4_CBC_SM3("ECDHE_SM4_CBC_SM3"
                              , 0xe011
                              ,ProtocolVersion.PROTOCOLS_OF_GMSSLs
                              ,KeyExchange.ECDHE,CipherAlg.SM4_CBC,MacAlg.SM3);

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

    enum KeyExchange{

        ECDHE("ECDHE"),
        ECC("ECC"),
        RSA("RSA");

        private final String name ;


        KeyExchange(String name) {
            this.name = name;
        }
    }
    enum CipherAlg{
        SM4_CBC("SM4_CBC"),
        SM4_GCM("SM4_CBC");
        private final String name ;


        CipherAlg(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    enum MacAlg{
        SM3("SM3"),
        SHA256("SHA256");

        private final String name ;


        MacAlg(String name) {
            this.name = name;
        }
        public String getName() {
            return name;
        }
    }

}
