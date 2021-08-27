# SAP CP Spring XSUAA Security Library 

## Integrate in a OAuth resource server

This library enhances the [spring-security](https://github.com/spring-projects/spring-security/) project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. A Spring boot application needs a security configuration class that enables the resource server and configures authentication using JWT tokens.

## Configuration

These (spring) dependencies needs to be provided:

### Maven Dependencies
```xml
<dependency> <!-- includes spring-security-oauth2 -->
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>spring-xsuaa</artifactId>
    <version>2.10.6</version>
</dependency>
<dependency> <!-- new with version 1.5.0 -->
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-to-slf4j</artifactId>
</dependency>
```

**Or, if you like to leverage auto-configuration:**

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>xsuaa-spring-boot-starter</artifactId>
    <version>2.10.6</version>
</dependency>
```

### Auto-configuration
As auto-configuration requires Spring Boot specific dependencies, it is enabled when using `xsuaa-spring-boot-starter` Spring Boot Starter. 
Then, xsuaa integration libraries auto-configures beans, that are required to initialize the Spring Boot application as OAuth resource server.

Auto-configuration class | Description
---- | --------
[XsuaaAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaAutoConfiguration.java) | Adds `xsuaa.*` properties to Spring's Environment. The properties are by default parsed from `VCAP_SERVICES` system environment variables and can be overwritten by properties such as `xsuaa.xsappname` e.g. for testing purposes. Furthermore it exposes a `XsuaaServiceConfiguration` bean that can be used to access xsuaa service information.  Alternatively you can access them with `@Value` annotation e.g. `@Value("${xsuaa.xsappname:}") String appId`.
[XsuaaResourceServerJwkAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaResourceServerJwkAutoConfiguration.java) | Configures a `JwtDecoder` bean with a JWK (JSON Web Keys) endpoint from where to download the tenant (subdomain) specific public key.
[XsuaaTokenFlowAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaTokenFlowAutoConfiguration.java) | Configures a `XsuaaTokenFlows` bean for a given `RestOperations` and `XsuaaServiceConfiguration` bean to fetch the XSUAA service binding information. Starting with `2.10.0` version it supports X.509 based authentication.

You can gradually replace auto-configurations as explained [here](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-auto-configuration.html).

#### RestTemplate / RestOperations

Please note, in case your application exposes already one or more Spring beans of type `RestOperations` (or its subclasses such as `RestTemplate`), `XsuaaAutoConfiguration` will not create a bean, but reuses the existing one. 

In case there are multiple ones the auto-configurations do not know, which `RestOperations` bean to select. In this case you can annotate the preferred `RestOperations` bean with `@Primary`.

In case you do not want to use the `RestOperations` bean, that is specified in your Spring application context but still like to leverage the auto-configuration of `spring-xsuaa` you can also provide a dedicated bean with name `xsuaaRestOperations`:

```java
@Configuration
public static class RestClientConfiguration {

    @Bean
    @LoadBalanced
    public OAuth2RestTemplate myOAuth2RestTemplate() {
        return new OAuth2RestTemplate(...);
    }

    @Bean
    public RestTemplate xsuaaRestOperations(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
        // Example that supports both: client secret and client certificate based authentication.
        // This is especially relevant if you want to leverage token exchange with XsuaaTokenFlows.
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(HttpClientFactory.create(clientIdentity)); // default implementation logs warning 
        RestOperations restOperations = new RestTemplate(requestFactory);         
    }

}
```

### Setup Security Context for HTTP requests
Configure the OAuth resource server

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    XsuaaServiceConfiguration xsuaaServiceConfiguration;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests()
            .antMatchers("/hello-token/**").hasAuthority("Read") // checks whether it has scope "<xsappId>.Read"
            .antMatchers("/actuator/**").authenticated()
            .anyRequest().denyAll()
        .and()
            .oauth2ResourceServer()
            .jwt()
            .jwtAuthenticationConverter(getJwtAuthoritiesConverter());
        // @formatter:on
    }

    Converter<Jwt, AbstractAuthenticationToken> getJwtAuthoritiesConverter() {
        TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
        converter.setLocalScopeAsAuthorities(true); // not applicable in case of multiple xsuaa bindings!
        return converter;
    }

}
```

### Setup Security Context for non-HTTP requests
In case of non-HTTP requests, you may need to initialize the Spring Security Context with a JWT token you've received from a message / event or you've requested from XSUAA directly:

```java
@Autowired 
XsuaaServiceConfiguration xsuaaServiceConfiguration;

@Autowired
JwtDecoder jwtDecoder;

public void onEvent(String myEncodedJwtToken) {
    if (myEncodedJwtToken != null) {
        SpringSecurityContext.init(myEncodedJwtToken, jwtDecoder, new LocalAuthoritiesExtractor(xsuaaServiceConfiguration.getAppId()));
    }
    try {
        handleEvent();
    } finally {
        SpringSecurityContext.clear();
    }
}
```

In detail `com.sap.cloud.security.xsuaa.token.SpringSecurityContext` wraps the Spring Security Context (namely `SecurityContextHolder.getContext()`), which stores by default the information in `ThreadLocal`s. In order to avoid memory leaks it is recommended to remove the current thread's value for garbage collection.

Note that Spring Security Context is thread-bound and is NOT propagated to child-threads. This [Baeldung tutorial: Spring Security Context Propagation article](https://www.baeldung.com/spring-security-async-principal-propagation) provides more information on how to propagate the context.


## Usage

### Access user/token information
In the Java coding, use the `Token` to extract user information:

```java
@GetMapping("/getGivenName")
public String getGivenName(@AuthenticationPrincipal Token token) {
    return token.getGivenName();
}
```

Or alternatively:
```java
public String getGivenName() {
    Token token = SpringSecurityContext.getToken();
    return token.getGivenName();
}
```

> Note: make sure that you've imported the right Token: `com.sap.cloud.security.xsuaa.token.Token`.


### Check authorization within a method

```java
@GetMapping(@AuthenticationPrincipal Token token)
public ResponseEntity<YourDto> readAll() {
    if (!token.getAuthorities().contains(new SimpleGrantedAuthority("Display"))) {
        throw new NotAuthorizedException("This operation requires \"Display\" scope");
    }
}

...

@ResponseStatus(HttpStatus.FORBIDDEN) //set status code to '403'
class NotAuthorizedException extends RuntimeException {
    public NotAuthorizedException(String message) {
        super(message);
    }
}
```

### Check authorization on method level
Spring Security supports authorization semantics at the method level. As prerequisite you need to enable global Method Security as explained in [Baeldung tutorial: Introduction to Spring Method Security](https://www.baeldung.com/spring-security-method-security).

```java
@GetMapping("/hello-token")
@PreAuthorize("hasAuthority('Display')")
public Map<String, String> message() {
    ...
}
```

### [Optional] Audit Logging
In case you have implemented a central Exception Handler as described with [Baeldung Tutorial: Error Handling for REST with Spring](https://www.baeldung.com/exception-handling-for-rest-with-spring) you may want to emit logs to the audit log service in case of `AccessDeniedException`s.

Alternativly there are also various options provided with `Spring.io`. For example, you can integrate SAP audit log service with Spring Boot Actuator audit framework as described [here](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-auditing).


## Troubleshoot

In case you face issues, [file an issue on Github](https://github.com/SAP/cloud-security-xsuaa-integration/issues/new)
and provide these details:
- security related dependencies, get maven dependency tree with `mvn dependency:tree`
- [debug logs](#increase-log-level-to-debug)
- [(SAP) Java buildpack version, e.g. 1.26.1](/java-security#get-buildpack-version)
- issue you’re facing.

### Increase log level to `DEBUG`

First, configure the Debug log level for Spring Framework Web and all Security related libs. This can be done as part of your `application.yml` or `application.properties` file.

```yaml
logging.level:
  com.sap: DEBUG                      # set SAP-class loggers to DEBUG. Set to ERROR for production setups.
  org.springframework: ERROR          # set to DEBUG to see all beans loaded and auto-config conditions met.
  org.springframework.security: DEBUG # set to ERROR for production setups. 
  org.springframework.web: DEBUG      # set to ERROR for production setups.
```

Then, in case you like to see what different filters are applied to particular request then set the debug flag to true in `@EnableWebSecurity` annotation:
```java
@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
   ...
}
```

Finally you need do re-deploy your application for the changes to take effect.

### Common Pitfalls
#### Compile error when upgrading from version `1.5.0` to `1.6.0`:  
  ```
  java.lang.IllegalStateException: Failed to load ApplicationContext
     Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'springSecurityFilterChain' defined in class path resource [org/springframework/security/config/annotation/web/configuration/WebSecurityConfiguration.class]: Bean instantiation via factory method failed; nested exception is org.springframework.beans.BeanInstantiationException: Failed to instantiate [javax.servlet.Filter]: Factory method 'springSecurityFilterChain' threw exception; nested exception is org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'org.springframework.security.oauth2.jwt.JwtDecoder' available
   ```  
   As of version `1.6.0` you need to make use of XSUAA Spring Boot Starter in order to leverage auto-configuration.
   Make use of the Xsuaa Spring Boot Starter dependency as explained [here](README.md#maven-dependencies).     

#### NoUniqueBeanDefinitionException, APPLICATION FAILED TO START
```
    Parameter 1 of method xsuaaJwtDecoder in com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration required a single bean, but 2 were found...
```
  In case you use the `xsuaa-spring-boot-starter`, read the [auto-configuration](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa#auto-configuration) section.

#### Multiple XSUAA Bindings (broker & application)  
If your application is bound to two XSUAA service instances (one of plan `application` and another one of plan `broker`), you run into the following issue:

```
Caused by: java.lang.RuntimeException: Found more than one xsuaa binding. There can only be one.
at com.sap.cloud.security.xsuaa.XsuaaServicesParser.getJSONObjectFromTag(XsuaaServicesParser.java:91)
at com.sap.cloud.security.xsuaa.XsuaaServicesParser.searchXSuaaBinding(XsuaaServicesParser.java:72)
at com.sap.cloud.security.xsuaa.XsuaaServicesParser.getAttribute(XsuaaServicesParser.java:59)
at com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory.getConfigurationProperties(XsuaaServicePropertySourceFactory.java:65)
at com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory.createPropertySource(XsuaaServicePropertySourceFactory.java:55)
at org.springframework.context.annotation.ConfigurationClassParser.processPropertySource(ConfigurationClassParser.java:452)
``` 

The library does not support more than one XSUAA binding. Follow [these steps](Migration_JavaContainerSecurityProjects.md#multiple-xsuaa-bindings), to adapt your **Spring Security Configuration**.

#### Configuration property name vcap.services.<<xsuaa instance name>>.credentials is not valid
We recognized that this error is raised, when your instance name contains upper cases. 
Alternatively you can then define your `XsuaaCredentials` Bean the following way:
```
@Bean
public XsuaaCredentials xsuaaCredentials() {
    final XsuaaCredentials result = new XsuaaCredentials();
    result.setXsAppName(environment.getProperty("vcap.services.<<xsuaa instance name>>.credentials.xsappname"));
    result.setClientId(environment.getProperty("vcap.services.<<xsuaa instance name>>.credentials.clientid"));
    result.setClientSecret(environment.getProperty("vcap.services.<<xsuaa instance name>>.credentials.clientsecret"));
    result.setUaaDomain(environment.getProperty("vcap.services.<<xsuaa instance name>>.credentials.uaadomain"));
    result.setUrl(environment.getProperty("vcap.services.<<xsuaa instance name>>.credentials.url"));
    return result;
}
```
#### ResourceAccessException during Token Exchange
In case you retrieve `ResourceAccessException` during token exchange similar to the one below, you need to make sure your `RestOperations` bean is configured with a SSL context. This needs to be equipped with the certificate of your uaa identity service provider. 
```
org.springframework.web.client.ResourceAccessException: I/O error on POST request for "https://xxx.authentication.cert.sap.hana.ondemand.com/oauth/token": readHandshakeRecord; nested exception is javax.net.ssl.SSLException: readHandshakeRecord
```
Find further information [here](/token-client) and [here](#resttemplate--restoperations).

#### Application crashes when no XsuaaTokenFlows could be found
If you have switched to X.509 credential type and your application crashes during start, then you may need to add a dependency to ``org.apache.httpcomponents:httpclient`` in order to auto-configure a default ``RestOperations`` bean ([XsuaaAutoConfiguration](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/autoconfiguration/XsuaaAutoConfiguration.java) ).
```
Field xsuaaTokenFlows in sample.spring.xsuaa.SecurityConfiguration required a bean of type 'com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows' that could not be found.
```   
#### JWT verification failed ... no suitable HttpMessageConverter found
In case `RestTemplate` is not configured with an appropriate `HttpMessageConverter` the Jwt signature validator can not handle the token keys (JWK set) response from xsuaa. Consequently the JWT signature can not be validated and it may fail with the following error:

```
JWT verification failed: An error occurred while attempting to decode the Jwt: Couldn't retrieve remote JWK set: org.springframework.web.client.RestClientException: Could not extract response: no suitable HttpMessageConverter found for response type [class java.lang.String] and content type [application/octet-stream]
```

In case you use 
```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
</dependency>

```
You can configure your xsuaa `RestTemplate` like that, e.g. as part of your `SecurityConfiguration` configuration class:
```java
@Bean
public RestOperations xsuaaRestOperations() {
    RestTemplate restTemplate = new RestTemplate();
    MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
    mappingJackson2HttpMessageConverter.setSupportedMediaTypes(Arrays.asList(MediaType.APPLICATION_JSON, MediaType.APPLICATION_OCTET_STREAM));
    restTemplate.getMessageConverters().add(mappingJackson2HttpMessageConverter);
    return restTemplate;
}
```

## Additional (test) utilities
- [java-security-test](./java-security-test) offers test utilities to generate custom JWT tokens for the purpose of tests. It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service (OAuth resource-server), e.g. to provide token keys for offline token validation. Its use is only intended for JUnit tests.

## Samples
- [Sample](/samples/spring-security-xsuaa-usage)    
demonstrating how to leverage xsuaa and spring security library to secure a Spring Boot web application including token exchange (user, client-credentials, refresh, ...). Furthermore it documents how to implement SpringWebMvcTests using `java-security-test` library.
- [Basic Auth Sample](/samples/spring-security-basic-auth)  
demonstrating how a user can access Rest API via basic authentication (user/password).


