package net.gmkai.util;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteBufferBuilder {

    private final int capacity;

    private ByteBufferOperation operation;

    private ByteBufferBuilder(int capacity) {
        this.capacity = capacity;
        this.operation = buffer -> {
        };
    }

    public static ByteBufferBuilder bufferCapacity(int capacity) {
        return new ByteBufferBuilder(capacity);
    }

    public ByteBufferBuilder operate(ByteBufferOperation operation) {
        this.operation = this.operation.andThen(operation);
        return this;
    }

    public ByteBuffer build() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(capacity);
        operation.operate(buffer);
        return buffer;
    }

    public byte[] buildByteArray() throws IOException {
        return build().array();
    }

}
