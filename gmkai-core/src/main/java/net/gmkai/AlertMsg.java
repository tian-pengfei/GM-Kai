package net.gmkai;

import javax.net.ssl.SSLException;
import java.util.Arrays;

public class AlertMsg implements Serializable {

    /**
     * The alert level enumerated.
     */
    private final Level level;

    /**
     * The alert description enumerated.
     */
    private final Description description;

    AlertMsg(Level level, Description description) {
        this.level = level;
        this.description = description;
    }

    public Description getDescription() {
        return description;
    }

    public Level getLevel() {
        return level;
    }

    @Override
    public byte[] toBytes() {
        return new byte[]{(byte) level.value, (byte) description.value};
    }

    public enum Level {
        UNKNOWN(-1, "unknow alert level"),
        WARNING(1, "warning"),
        FATAL(2, "fatal");
        private final int value;
        private final String name;

        Level(int value, String name) {
            this.value = value;
            this.name = name;
        }

        public static Level getInstance(int value) {
            if (value == 1) {
                return WARNING;
            }
            if (value == 2) {
                return FATAL;
            }

            return UNKNOWN;
        }
    }

    public enum Description {
        UNKNOWN(-1, "unknown description"),
        CLOSE_NOTIFY(0, "close_notify"),
        UNEXPECTED_MESSAGE(10, "unexpected_message"),
        BAD_RECORD_MAC(20, "bad_record_mac"),
        DECRYPTION_FAILED(21, "decryption_failed"),
        RECORD_OVERFLOW(22, "record_overflow"),
        DECOMPRESION_FAILURE(30, "decompresion_failure"),
        HANDSHAKE_FAILURE(40, "handshake_failure"),
        BAD_CERTIFICATE(42, "bad_certificate"),
        UNSUPPORTED_CERTIFICATE(43, "unsupported_certificate"),
        CERTIFICATE_REVOKED(44, "certificate_revoked"),
        CERTIFICATE_EXPIRED(45, "certificate_expired"),
        CERTIFICATE_UNKNOWN(46, "certificate_unknown"),
        ILEGAL_PARAMETER(47, "illegal_parameter"),
        UNKNOWN_CA(48, "unknown_ca"),
        ACES_DENIED(49, "acces_denied"),
        DECODE_ERROR(50, "decode_error"),
        DECRYPT_ERROR(51, "decrypt_error"),
        PROTOCOL_VERSION(70, "protocol_version"),
        INSUFICIENT_SECURITY(71, "insuficient_security"),
        INTERNAL_ERROR(80, "internal_eror"),
        USER_CANCELED(90, "user_canceled"),
        NO_RENEGOTIATION(100, "no renegotiation"),
        UNSUPPORTED_SITE2SITE(200, "unsupported_site2site"),
        NO_AREA(201, "no_area"),
        UNSUPPORTED_AREATYPE(202, "unsupported_areatype"),
        BAD_IBCPARAM(203, "bad_ibcparam"),
        UNSUPPORTED_IBCPARAM(204, "unsupported_ibcparam"),
        IDENTITY_NEED(205, "identity_need");


        private final int value;
        private final String name;

        Description(int value, String name) {
            this.value = value;
            this.name = name;
        }

        public static Description getInstance(int value) {
            return Arrays.stream(values()).
                    filter(d -> d.value == value).
                    findFirst().orElse(UNKNOWN);
        }

        @Override
        public String toString() {
            return name;
        }
    }


    public static AlertMsg getInstance(byte[] fragment) throws SSLException {
        if (fragment.length != 2) throw new SSLException("");

        Level level = Level.getInstance(fragment[0]);
        Description desc = Description.getInstance(fragment[1]);
        return new AlertMsg(level, desc);
    }
}
