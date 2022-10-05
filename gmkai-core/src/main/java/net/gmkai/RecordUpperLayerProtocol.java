package net.gmkai;


import java.io.IOException;

public interface RecordUpperLayerProtocol {

    void handleMsgFromOtherProtocol(TLSText tlsText) throws IOException;

}
