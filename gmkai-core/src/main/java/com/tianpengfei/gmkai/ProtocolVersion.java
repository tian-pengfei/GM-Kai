package com.tianpengfei.gmkai;

import javax.net.ssl.SSLException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum ProtocolVersion {

    NULL(0x0000, "NULL"),
    GMSSL11(0x0101, "GMSSLv1.1");

    final int id;

    final String name;



    final byte major;

    final byte minor;

    ProtocolVersion(int id, String name) {
        this.id = id;
        this.name = name;
        this.major = (byte) ((id >>> 8) & 0xFF);
        this.minor = (byte) (id & 0xFF);
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
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

    static final ProtocolVersion[] PROTOCOLS_OF_GMSSLs = new ProtocolVersion[]{
            GMSSL11
    };

    static String nameOf(byte major, byte minor) throws SSLException {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if ((pv.major == major) && (pv.minor == minor)) {
                return pv.name;
            }
        }

        throw new SSLException("不支持此协议");
    }


    static String[] nameOf(List<ProtocolVersion> protocolVersions) {
        if ((protocolVersions != null) && !protocolVersions.isEmpty()) {
            String[] protocolNames = new String[protocolVersions.size()];
            int i = 0;
            for (ProtocolVersion pv : protocolVersions) {
                protocolNames[i++] = pv.name;
            }

            return protocolNames;
        }

        return new String[0];
    }
    static ProtocolVersion valueof(String protocolVersion) {
        return Arrays.stream(values())
                .filter(p->p.name.equals(protocolVersion))
                .findFirst().orElse(NULL);
    }
    static List<ProtocolVersion> nameOf(String[] protocolVersions) {

       return  Arrays.stream(protocolVersions)
               .map(ProtocolVersion::valueof)
               .collect(Collectors.toList());
    }
}
