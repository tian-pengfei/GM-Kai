package net.gmkai;

import java.io.IOException;

public interface AlertSender {

    void sendAlert(final byte[] data) throws IOException;
}
