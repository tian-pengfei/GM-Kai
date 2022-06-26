package com.tianpengfei.gmkai;

public interface SSLConsumer<T extends ConnectionContext, V> {
    void consume(T t,V v);
}
