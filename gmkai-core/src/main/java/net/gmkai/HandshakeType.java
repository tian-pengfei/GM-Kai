package net.gmkai;


import java.util.Arrays;
import java.util.Optional;

enum HandshakeType {

    HELLO_REQUEST((byte) 0x00, "hello_request"),

    CLIENT_HELLO((byte) 0x01, "client_hello"),

    SERVER_HELLO((byte) 0x02, "server_hello"),

    CERTIFICATE((byte) 0x0B, "certificate"),

    SERVER_KEY_EXCHANGE((byte) 0x0C, "server_key_exchange"),

    CERTIFICATE_REQUEST((byte) 0x0D, "certificate_request"),

    SERVER_HELLO_DONE((byte) 0x0E, "server_hello_done"),

    CERTIFICATE_VERIFY((byte) 0x0F, "certificate_verify"),

    CLIENT_KEY_EXCHANGE((byte) 0x10, "client_key_exchange"),

    FINISHED((byte) 0x14, "finished");

    final byte id;

    final String name;

    HandshakeType(byte id, String name) {
        this.id = id;
        this.name = name;
    }

    public static Optional<HandshakeType> valueOf(byte id) {
        return Arrays.stream(HandshakeType.values())
                .filter(sht -> sht.id == id).findFirst();
    }
}
