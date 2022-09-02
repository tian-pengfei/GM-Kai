package net.gmkai.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;


@FunctionalInterface
public interface ByteBufferOperation {

    void operate(ByteBuffer buffer) throws IOException;

    default ByteBufferOperation andThen(ByteBufferOperation after) {
        Objects.requireNonNull(after);
        return (ByteBuffer t) -> {
            operate(t);
            after.operate(t);
        };
    }

}
