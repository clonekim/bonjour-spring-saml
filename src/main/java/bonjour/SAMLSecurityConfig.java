package bonjour;


import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SAMLProperties.class)
public class SAMLSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    SAMLProperties samlProperties;

    @Autowired
    SAMLUserDetailsService samlUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .exceptionHandling()
                .authenticationEntryPoint(samlEntryPoint())
                .and()
                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
                .authorizeRequests()

                .antMatchers(
                        samlProperties.getNotAuthorized().stream().toArray(String[]::new)
                      ).permitAll().anyRequest().authenticated()
        ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(
                "/**/*.css",
                "/**/*.map",
                "/**/*.ico",
                "/**/*.js",
                "/**/*.gif",
                "/**/*.jpg",
                "/**/*.jpeg",
                "/**/*.png",
                "/**/*.ttf",
                "/**/*.woff",
                "/**/*.woff2",
                "/**/*.otf",
                "/**/*.html",
                "/**/*.htm",
                "/**/*.json"
        );
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(samlUserDetailsService);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        //credential를 저장안하려면 true설정
        //SingleLogout 사용안할경우
        //samlAuthenticationProvider.setExcludeCredential(true);

        return samlAuthenticationProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider());
    }

    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();
        profileOptions.setIncludeScoping(false);
        profileOptions.setBinding(org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI);
        profileOptions.setAllowCreate(false);
        profileOptions.setForceAuthN( samlProperties.getSp().forceAuthN);

        if (samlProperties.getSp().relayState != null) {
            profileOptions.setRelayState(samlProperties.getSp().relayState);
        }
        samlEntryPoint.setDefaultProfileOptions(profileOptions);
        return samlEntryPoint;
    }

    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        WebSSOProfileConsumerImpl ssoProfileConsumer = new WebSSOProfileConsumerImpl();

        if(samlProperties.getSp().maxAuthenticationAge > 0)
            ssoProfileConsumer.setMaxAuthenticationAge( samlProperties.getSp().maxAuthenticationAge);

        return ssoProfileConsumer;
    }


    // SSO Holder of Key
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }


    @Bean
    public SingleLogoutProfile singleLogoutProfile() {
        return new SingleLogoutProfileImpl();
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    public CachingMetadataManager metadata() throws MetadataProviderException {
        return new CachingMetadataManager(Arrays.asList(
                idpMetadata()
        ));
    }

    @Bean
    public KeyManager keyManager() {
        Map<String, String> passwords = new HashMap();
        passwords.put(samlProperties.getKeyStore().getAlias(), samlProperties.getKeyStore().getKeypass());
        return new JKSKeyManager(
                samlProperties.getKeyStore().getFile(),
                samlProperties.getKeyStore().getStorepass(),
                passwords,
                samlProperties.getKeyStore().getAlias());
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setSigningAlgorithm(samlProperties.getSp().signingAlgorithm);
        extendedMetadata.setSignMetadata(false);
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setEcpEnabled(false);
        return extendedMetadata;
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        if (samlProperties.getSp().getEntityId() != null)
            metadataGenerator.setEntityId(samlProperties.getSp().entityId);
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        if (samlProperties.getSp().getEntityBaseUrl() != null)
            metadataGenerator.setEntityBaseURL(samlProperties.getSp().entityBaseUrl);
        return metadataGenerator;
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        return new FilterChainProxy(Arrays.asList(
                new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login"), samlEntryPoint()),
                new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout"), samlLogoutFilter()),
                new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout"), samlLogoutProcessingFilter()),
                new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata"), metadataDisplayFilter()),
                new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO"), ssoProcessingFilter())
        ));
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public SAMLProcessingFilter ssoProcessingFilter() throws Exception {
        SAMLProcessingFilter processingFilter = new SAMLProcessingFilter();
        processingFilter.setAuthenticationManager(authenticationManager());
        processingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        processingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return processingFilter;
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl(samlProperties.getSp().loginUrl);
        return successRedirectHandler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl(samlProperties.getSp().errorUrl);
        return failureHandler;
    }

    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl(samlProperties.getSp().logoutUrl);
        successLogoutHandler.setAlwaysUseDefaultTargetUrl(samlProperties.getSp().alwaysUseDefaultTargetUrl);

        return successLogoutHandler;
    }

    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
    }


    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    }


    @Bean
    public ExtendedMetadataDelegate idpMetadata() throws MetadataProviderException {
        Timer timer = new Timer(true);
        ResourceBackedMetadataProvider provider = new ResourceBackedMetadataProvider(timer, samlProperties.getIdp().getMetadataUrl());
        provider.setParserPool(parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(provider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(samlProperties.getIdp().metadataTrust);
        extendedMetadataDelegate.setMetadataRequireSignature(samlProperties.getIdp().requireSignature);
        timer.purge();
        return extendedMetadataDelegate;
    }

    @Bean
    public SAMLProcessorImpl processor() {
        return new SAMLProcessorImpl(Arrays.asList(
                httpPostBinding(),
                httpRedirectDeflateBinding()
        ));
    }

    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), VelocityFactory.getEngine());
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }
}
