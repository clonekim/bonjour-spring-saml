# Bonjour! SAML

## Sample Application

saml를 구동하기 위해서 반드시 아래의 컴포넌트만 구현하면 된다.
1. SAMLUserDetailService
1. SAMLContextProvider
 단일 서버나 로드밸런스를 둘경우 provider가 달라진다.
1. application.yml 준비


```java

import bonjour.SAMLSecurityConfig;
import com.koreanair.config.AuthExcludedGrantClasses;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.storage.EmptyStorageFactory;

import java.util.Arrays;

@Slf4j
@SpringBootApplication
@Import(SAMLSecurityConfig.class)
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }


    @Configuration
    @Profile(value = {"dev"})
    static class SAMLContxtLocalConfig {
        @Bean
        SAMLContextProvider samlContextProvider() {
            log.info("Creating SAMLContextProvider");
            SAMLContextProviderImpl contextProvider = new SAMLContextProviderImpl();
            contextProvider.setStorageFactory(new EmptyStorageFactory());
            return contextProvider;
        }

    }

    @Configuration
    @Profile(value = {"aws"})
    static class SAMLContextLBConfig {

        @Bean
        public SAMLContextProvider samlContextProvider(@Value("${lb}") String lb) {

            String schema = lb.substring(0, lb.indexOf("//") -1);
            String serverName = lb.substring(lb.indexOf("//") + 2, lb.lastIndexOf(":"));
            int port = Integer.parseInt(lb.substring(lb.lastIndexOf(":") +1 ));

            log.info("Creating SAMLContextProviderLB => schema:{}, port:{}, name:{}",
                    schema,
                    port,
                    serverName);

            SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
            contextProvider.setStorageFactory(new EmptyStorageFactory());
            contextProvider.setServerPort(port);
            contextProvider.setScheme(schema);
            contextProvider.setServerName(serverName);
            contextProvider.setContextPath("/");
            contextProvider.setIncludeServerPortInRequestURL(false);

            return contextProvider;
        }
    }

}

```


```java
@Component
public class SAMLUserDetailServiceImpl implements SAMLUserDetailsService  {



    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        log.info("Returning NameID ==> {} or credentials ==> {}", credential.getNameID().getValue(), credential);


    //  return UserDetail구현체를 돌려준다

    }
}

```

## Keystore 생성

```
keytool -genkey -alias samlkey \
-keyalg RSA \
-keysize 2048  \
-sigalg SHA256withRSA \
-validity 735 \
-keypass secret \
-storepass secret \
-keystore keystore.jks
```

```application.yml
sso:
  idp:
    metadata-trust: false
    metadata-require-signature: true
  sp:
    entity-id: 당신의 SP의 엔티티아이디
    signing-algorithm: http://www.w3.org/2000/09/xmldsig#rsa-sha1
    login-url: /secured
  key-store:
    file: classpath:jks 파일
    alias: samlKey
    key-pass: secret
    store-pass: secret

```
