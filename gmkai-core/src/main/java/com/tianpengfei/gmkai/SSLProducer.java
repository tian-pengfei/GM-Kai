package com.tianpengfei.gmkai;

public interface SSLProducer<T extends ConnectionContext, R> {

    R produce(T t);
}
