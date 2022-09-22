package net.gmkai;

import java.util.Arrays;
import java.util.Optional;

public enum CompressionMethod {

    // not support compress

    NULL(0);

    public final int id;

    CompressionMethod(int id) {
        this.id = id;
    }

    public static Optional<CompressionMethod> valueOf(byte encodedId) {

        return Arrays.stream(CompressionMethod.values()).
                filter(compressionMethod -> compressionMethod.id == encodedId).
                findFirst();

    }

    public int getId() {
        return id;
    }
}
