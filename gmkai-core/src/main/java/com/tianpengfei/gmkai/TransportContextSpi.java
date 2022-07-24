package com.tianpengfei.gmkai;

import com.tianpengfei.gmkai.application.AppInputStream;
import com.tianpengfei.gmkai.application.AppOutputStream;

public interface TransportContextSpi {

    GMSSLSession getSession();

    GMSSLSession getHandshakeSession();

    AppInputStream getInputStream();

    AppOutputStream getOutputStream();


}
