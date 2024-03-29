package net.gmkai;

import javax.net.ssl.SSLException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public enum ProtocolVersion {

    NULL(0x0000, "NULL"),

    TLCP11(0x0101, "TLCP1.1"),

    TLS13(0x0304, "TLSv1.3"),

    TLS12(0x0303, "TLSv1.2");
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

    public static Optional<ProtocolVersion> valueOf(int id) {

        return Arrays.stream(ProtocolVersion.values()).
                filter(pv -> pv.id == id).
                findFirst();

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


    public static String[] namesOf(List<ProtocolVersion> protocolVersions) {

        if (protocolVersions == null) return new String[0];

        return protocolVersions.stream()
                .map(protocolVersion -> protocolVersion.name)
                .toArray(String[]::new);
    }

    public static Optional<ProtocolVersion> nameOf(String protocolVersion) {
        return Arrays.stream(values())
                .filter(p -> p.name.equals(protocolVersion))
                .findFirst();
    }

    public static List<ProtocolVersion> namesOf(String[] protocolVersions) {

        return Arrays.stream(protocolVersions).
                map(ProtocolVersion::nameOf).
                filter(Optional::isPresent).
                map(Optional::get).
                collect(Collectors.toList());
    }
}
