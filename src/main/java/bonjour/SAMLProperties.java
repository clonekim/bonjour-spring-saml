package bonjour;

import lombok.Getter;
import lombok.Setter;
import org.opensaml.util.resource.ClasspathResource;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@Getter
@Setter
@ConfigurationProperties(prefix = "sso")
public class SAMLProperties {
    private IdpProperties idp;
    private SpProperties sp;
    private KeyStoreProperties keyStore;

    @Getter
    @Setter
    public static class IdpProperties {
        boolean metadataTrust;
        boolean requireSignature;
        ClasspathResource metadataUrl;
    }

    @Getter
    @Setter
    public static class SpProperties {
        String entityId;
        String entityBaseUrl;
        String signingAlgorithm;
        String loginUrl = "/";
        String logoutUrl = "/";
        String errorUrl = "/error";
        String relayState;
        boolean forceAuthN;
        // int responseSkew;
    }

    @Getter
    @Setter
    public static class KeyStoreProperties {
        private Resource file;
        private String keypass;
        private String alias;
        private String storepass;
    }

}