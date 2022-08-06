package com.tianpengfei.gmkai;

import javax.net.ssl.SSLException;
import java.io.IOException;

public interface SSLProducer<T extends ConnectionContext, R> {

    R produce(T t) throws SSLException, IOException;
}
