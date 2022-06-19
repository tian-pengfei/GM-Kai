package com.tianpengfei.gmkai;

public enum ProtocolVersion {

    GMSSL11(0x0101,  "GMSSLv1.1");

    final int id;

    final String name;

    final byte major;

    final byte minor;

    ProtocolVersion(int id, String name) {
        this.id = id;
        this.name = name;
        this.major = (byte)((id >>> 8) & 0xFF);
        this.minor = (byte)(id & 0xFF);
    }

    static ProtocolVersion valueOf(byte major, byte minor) {

        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if ((pv.major == major) && (pv.minor == minor)) {
                return pv;
            }
        }

        return null;
    }
    static ProtocolVersion valueOf(int id) {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (pv.id == id) {
                return pv;
            }
        }
        return null;
    }

    static final ProtocolVersion[] PROTOCOLS_OF_GMSSLs = new ProtocolVersion[] {
            GMSSL11
    };

}
