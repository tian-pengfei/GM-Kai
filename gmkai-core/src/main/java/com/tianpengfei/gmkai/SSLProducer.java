package com.tianpengfei.gmkai;

public interface SSLProducer<T extends ConnectionContext> {

    void product(T t);
}
