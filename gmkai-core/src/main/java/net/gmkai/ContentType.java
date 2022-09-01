package net.gmkai;


import java.util.Arrays;
import java.util.Optional;

public enum ContentType {

    CHANGE_CIPHER_SPEC((byte) 20, "change_cipher_spec",
            ProtocolVersion.GM_PROTOCOLS),

    ALERT((byte) 21, "alert",
            ProtocolVersion.GM_PROTOCOLS),

    HANDSHAKE((byte) 22, "handshake",
            ProtocolVersion.GM_PROTOCOLS),

    APPLICATION_DATA((byte) 23, "application_data",
            ProtocolVersion.GM_PROTOCOLS);

    final public byte id;

    final public String name;

    final ProtocolVersion[] supportedProtocols;

    ContentType(byte id, String name, ProtocolVersion[] supportedProtocols) {
        this.id = id;
        this.name = name;
        this.supportedProtocols = supportedProtocols;
    }

    public static Optional<ContentType> valueOf(int id) {
        return Arrays.stream(ContentType.values()).filter(contentType -> contentType.id == id)
                .findFirst();
    }
}
