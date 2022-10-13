# GMKai

支持 TLCP(GMSSL)协议的JSSE.

## 状态

开发完善中...



## 环境

java8+



## 使用

详细代码查看MainTest.java

### 前提

```java
	 @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        sslContext = SSLContext.getInstance("TLCP");
        keyManagerFactory = KeyManagerFactory.getInstance("TLCPX509");
        trustManagerFactory = TrustManagerFactory.getInstance("TLCPX509");
    }
```



### 客户端使用

```java
	 @Test
    public void should_client_request() throws IOException, KeyManagementException, CertificateException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException {

        KeyStore keyStore = loadKeyStoreFromTrustedListPem("src/test/resources/trusted.certs.pem");

        trustManagerFactory.init(keyStore);

        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory ssf = sslContext.getSocketFactory();

        String result = sendHttpGetRequest(ssf, remoteServerUrl);

        assertThat(result, containsStringIgnoringCase("<html>"));
    }
```



### 服务端使用

使用了aliyun/gm-jsse 辅助测试

```java
	@Test
    public void should_server_handle_request() throws Exception {

        KeyStore keyStore = loadKeyStoreFromPFX("src/test/resources/sm2.gmkai.pfx", "12345678");

        keyManagerFactory.init(keyStore, "12345678".toCharArray());

        sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        asyncExecute(() -> httpServerStart(8443, sslServerSocketFactory, response));

        String re = sendHttpGetRequestByTLCP1_1("https://localhost:8443/");
        assertThat(re, equalTo(response));
    }
```



### 服务端和客户端互通测试



```java
	 @Test
    public void should_client_request_server() throws Exception {


        KeyStore serverKeyStore = loadKeyStoreFromPFX("src/test/resources/sm2.gmkai.pfx", "12345678");

        KeyStore clientKeyStore = loadKeyStoreFromTrustedListPem("src/test/resources/trusted.certs.pem");

        keyManagerFactory.init(serverKeyStore, "12345678".toCharArray());

        trustManagerFactory.init(clientKeyStore);

        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        asyncExecute(() -> httpServerStart(9443, sslServerSocketFactory, response));

        SSLSocketFactory ssf = sslContext.getSocketFactory();

        String re = sendHttpGetRequest(ssf, "https://localhost:9443/");

        assertThat(re, equalTo(response));
    }
```



## 支持情况

+ TLCP1_1
  + 单向，暂不支持双向认证
  + 加密套件：ECC_SM4_CBC_SM3



## 许可证

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)











