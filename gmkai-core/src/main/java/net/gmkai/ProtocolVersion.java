package net.gmkai;

import javax.net.ssl.SSLException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public enum ProtocolVersion {

    NULL(0x0000, "NULL"),
    TLCP11(0x0101, "TLCP1.1");

    final int id;

    final String name;

    final byte major;

    final byte minor;

    public static final ProtocolVersion[] GM_PROTOCOLS = new ProtocolVersion[]{
            TLCP11
    };

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

    public static Optional<ProtocolVersion> valueOf(byte major, byte minor) {

        return Arrays.stream(values())
                .filter(pv -> pv.major == major && pv.minor == minor).findFirst();
    }

    public static ProtocolVersion valueOf(int id) {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (pv.id == id) {
                return pv;
            }
        }
        return null;
    }

    public static final ProtocolVersion[] PROTOCOLS_OF_GMSSLs = new ProtocolVersion[]{
            TLCP11
    };

    public static String nameOf(byte major, byte minor) throws SSLException {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if ((pv.major == major) && (pv.minor == minor)) {
                return pv.name;
            }
        }

        throw new SSLException("This protocol is not supported");
    }


    public static String[] nameOf(List<ProtocolVersion> protocolVersions) {

        if (protocolVersions == null) return new String[0];

        return (String[]) protocolVersions.stream()
                .map(protocolVersion -> protocolVersion.name)
                .toArray();
    }

    public static Optional<ProtocolVersion> nameOf(String protocolVersion) {
        return Arrays.stream(values())
                .filter(p -> p.name.equals(protocolVersion))
                .findFirst();
    }

    public static List<ProtocolVersion> nameOf(String[] protocolVersions) {

        return Arrays.stream(protocolVersions)
                .map(ProtocolVersion::valueOf)
                .collect(Collectors.toList());
    }
}
