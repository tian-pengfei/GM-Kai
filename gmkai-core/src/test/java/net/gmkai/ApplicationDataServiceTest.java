package net.gmkai;

import net.gmkai.event.GMKaiEventBus;
import net.gmkai.event.TLSEventBus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class ApplicationDataServiceTest {

    private ApplicationDataService applicationDataService;

    private TLSEventBus tlsEventBus;

    private ApplicationMsgTransport applicationMsgTransport;


    @BeforeEach
    public void setUp() {

        tlsEventBus = new GMKaiEventBus();

        applicationMsgTransport = mock(ApplicationMsgTransport.class);

        applicationDataService = new ApplicationDataService(tlsEventBus, applicationMsgTransport);
    }

    @Test
    public void should_write_app_data() throws IOException {
        OutputStream outputStream = applicationDataService.getAppOutStream();

        outputStream.write(new byte[]{1, 2, 3, 4});

        verify(applicationMsgTransport).writeApplicationMsg(isA(byte[].class));
    }

    @Test
    public void should_read_app_data() throws IOException {

        String originalString = "I love you";

        when(applicationMsgTransport.readApplicationMsg()).thenReturn(
                new TLSText(
                        ContentType.APPLICATION_DATA,
                        ProtocolVersion.TLCP11,
                        originalString.getBytes(StandardCharsets.UTF_8))).thenReturn(null);

        InputStream inputStream = applicationDataService.getAppInputStream();

        String actual = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.joining("\n"));

        assertThat(actual, is(actual));

    }
}
