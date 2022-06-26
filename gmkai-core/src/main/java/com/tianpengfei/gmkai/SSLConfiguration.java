package com.tianpengfei.gmkai;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import java.security.AlgorithmConstraints;
import java.util.Collection;
import java.util.List;

final class  SSLConfiguration {


    // configurations with SSLParameters
    AlgorithmConstraints userSpecifiedAlgorithmConstraints;
    List<ProtocolVersion> enabledProtocols;
    List<CipherSuite>           enabledCipherSuites;
    ClientAuthType clientAuthType;
    String                      identificationProtocol;
    List<SNIServerName>         serverNames;
    Collection<SNIMatcher> sniMatchers;
    String[]                    applicationProtocols;
    boolean                     preferLocalCipherSuites;
    int                         maximumPacketSize = 0;


    // Configurations per SSLSocket or SSLEngine instance.
    boolean                     isClientMode;
    boolean                     enableSessionCreation;

}
