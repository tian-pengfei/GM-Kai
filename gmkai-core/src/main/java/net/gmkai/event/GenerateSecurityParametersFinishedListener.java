package net.gmkai.event;

import com.google.common.eventbus.Subscribe;

public interface GenerateSecurityParametersFinishedListener extends TLSListener {

    @Subscribe
    void setSecurityParameters(GenerateSecurityParametersFinishedEvent event);

}
