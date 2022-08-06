package com.tianpengfei.gmkai;

import java.io.IOException;

public interface SSLConsumer<T extends ConnectionContext, V> {
    void consume(T context, V message) throws IOException;
}
