package com.tianpengfei.gmkai.handshake;


import com.tianpengfei.gmkai.TransportContext;

/**
 * 用于协商协议和加密套件
 */
public class ProtocolNegotiator {

    private TransportContext connectContext;

    ProtocolNegotiator(TransportContext connectContext) {
        this.connectContext = connectContext;
    }

    public void kickstart(TransportContext tc) {

    }

}
