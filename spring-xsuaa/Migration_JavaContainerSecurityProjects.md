# Migration Guide for Applications that use Spring Security and java-container-security

This migration guide is a step-by-step guide explaining how to replace the following SAP-internal Java Container Security Client libraries
- com.sap.xs2.security:java-container-security
- com.sap.cloud.security.xsuaa:java-container-security

with this open-source version.

**Please note, that this Migration Guide is NOT intended for applications that leverage token validation and authorization checks using SAP Java Buildpack.** This [sample](https://github.com/SAP/cloud-security-services-integration-library/tree/main/samples/sap-java-buildpack-api-usage) showcases the setup when using SAP Java Buildpack.

## Overview

The following list serves as an overview of this guide and points out sections that describe required code changes for migrating applications.

- Spring 5 is required! See section [Prerequisite](#prerequisite--migrate-to-spring-5-and-spring-security-52).
- Maven dependencies need to be changed. See section [Maven Dependencies](#maven-dependencies).
- The Spring Security configuration needs changes described in section [Configuration changes](#configuration-changes).
- `Token` instead of `XSUserInfo`. See section [Fetch data from token](#fetch-data-from-token).
- If your application has multiple XSUAA bindings, see section [Multiple bindings](#multiple-xsuaa-bindings).

## Prerequisite: Migrate to Spring 5 and Spring Security 5.2

If your application does not already use Spring 5 you need to upgrade to Spring
5 first to use [spring-xsuaa](/spring-xsuaa).
Likewise if you use Spring Boot make sure that you use Spring Boot 2.

Your application is probably using Spring Security OAuth 2.x which is being deprecated with
Spring 5. The successor is Spring Security 5.2.x but it is not compatible with Spring
Security OAuth 2.x. See the
[official migration guide](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide)
for more information.

We already migrated the [cloud-bulletinboard-ads](https://github.com/SAP-samples/cloud-bulletinboard-ads/)
application. You can take a look at 
[this commit](https://github.com/SAP-samples/cloud-bulletinboard-ads/commit/b6cc7b08b9b5b7862b1a04eb3bc72cb3c28626f8)
which shows what had to be changed to migrate our open-SAP course application from Spring 4 to Spring 5.

:bulb: Please also consider the [spring-xsuaa](/README.md#requirements) requirements.

## Maven Dependencies
To use the new [spring-xsuaa](/spring-xsuaa) client library the dependencies declared in maven `pom.xml` need to be changed.
See the [documentation](/spring-xsuaa#configuration) on what to add to your `pom.xml`.

Now you are ready to **remove** the **`java-container-security`** client library by deleting the following dependencies from the pom.xml:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.xs2.security | java-container-security
com.sap.xs2.security | api
com.sap.cloud.security.xssec | api 
com.sap.cloud.security.xsuaa | java-container-security-api
com.sap.cloud.security.xsuaa | java-container-security
com.sap.cloud.security.xsuaa | api

> Note: The dependency `com.sap.cloud.security.xsuaa:api` should be removed as well, as `spring-xsuaa` provides it already as transitive dependency.

Furthermore, make sure that you do not refer to any other sap security library with groupId `com.sap.security` or `com.sap.security.nw.sso.*`.

## Configuration changes
After the dependencies have been changed, the spring security configuration needs some adjustments as well.

One difference between `java-container-security` and [spring-xsuaa](/spring-xsuaa) is that spring-xsuaa
does not provide the `SAPOfflineTokenServicesCloud` class. This is because `SAPOfflineTokenServicesCloud` requires 
Spring Security OAuth 2.x which is being deprecated in Spring 5.

This means that you have to remove the  `SAPOfflineTokenServicesCloud` bean from your security configuration
and adapt the `HttpSecurity` configuration. This involves the following steps:

- The `@EnableResourceServer` annotation must be removed. Instead, the resource server has to be configured using the Spring Security DSL syntax.   
See the [docs](/spring-xsuaa/#setup-security-context-for-http-requests) for an example configuration.
- The `antMatchers` must be configured to check against the authorities. For this the `TokenAuthenticationConverter`
  needs to be configured like described in the [docs](/spring-xsuaa/#setup-security-context-for-http-requests). Note: with the removal of the deprecated [Spring Security OAuth](https://projects.spring.io/spring-security-oauth) library the web expression `access("#oauth2.hasScope('" + xsAppName + ".Display"’)")` has been removed, and must be replaced with `hasAuthority("Display")`.

We already added `spring-xsuaa` and `java-security-test` to the [cloud-bulletinboard-ads](https://github.com/SAP-samples/cloud-bulletinboard-ads) application and
[this commit](https://github.com/SAP-samples/cloud-bulletinboard-ads/commit/585c7a1a9763c627009fda03a6424e0328df3c5a)
shows the security relevant parts.

### Access VCAP_SERVICES values
There are two options to access information of the XSUAA service instance (`VCAP_SERVICES` credentials):

1. Via Spring `@Value`
```java
@Value("${xsuaa.xsappname}")
String xsAppName;
```
2. Via XsuaaServiceConfiguration bean
```java
@Autowired
XsuaaServiceConfiguration xsuaaServiceConfiguration;

...

xsuaaServiceConfiguration.getAppId();
```



### SAP_JWT_TRUST_ACL obsolete
There is no need to configure `SAP_JWT_TRUST_ACL` within your deployment descriptor such as `manifest.yml`. 
Instead the Xsuaa service instance adds audiences to the issued JSON Web Token (JWT) as part of the `aud` claim.

Whether the token is issued for your application or not is now validated by the [`XsuaaAudienceValidator`](/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/token/authentication/XsuaaAudienceValidator.java).

This comes with a change regarding scopes. For a business application A that wants to call an application B, it's now mandatory that the application B grants at least one scope to the calling business application A. You can grant scopes with the `xs-security.json` file. For additional information, refer to the [Application Security Descriptor Configuration Syntax](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html), specifically the sections [referencing the application](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html#loio517895a9612241259d6941dbf9ad81cb__section_fm2_wsk_pdb) and [authorities](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html#loio517895a9612241259d6941dbf9ad81cb__section_d1m_1nq_zy). 

### Multiple XSUAA Bindings
You can skip this section, in case your application is bound to only one Xsuaa service instance. The `xsuaa-spring-boot-starter` does not support multiple XSUAA bindings of plan `application` and `broker`. **The Xsuaa service instance of plan `api` get always ignored.**

In case of multiple bindings you need to adapt your **Spring Security Configuration** as following:

1. You need to get rid of  `XsuaaServicePropertySourceFactory`, because `XsuaaServicesParser` raises the error.
 * In case you make use of `xsuaa-spring-boot-starter` Spring Boot starter, you need to disable auto-configuration within your `*.properties` / or `*.yaml` file:
    ```java
    spring.xsuaa.multiple-bindings = true
    ```
 * Or, make sure that your code does not contain
    ```java
    @PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = {""})
    ```
2. Instead, provide your own implementation of `XsuaaSecurityConfiguration` interface to access the **primary Xsuaa service configuration** of your application (chose the service instance of plan `application` here), which are exposed in the `VCAP_SERVICES` system environment variable (in Cloud Foundry). 
Starting with version `2.6.2` you can implement it like that: 

    ```java
    import com.sap.cloud.security.xsuaa.XsuaaCredentials;
    import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationCustom;
   
    ...
   
    @Bean
    @ConfigurationProperties("vcap.services.<<name of your xsuaa instance of plan application>>.credentials")
    public XsuaaCredentials xsuaaCredentials() {
        return new XsuaaCredentials(); // primary Xsuaa service binding, e.g. application
    }

    @Bean
    public XsuaaServiceConfiguration customXsuaaConfig() {
        return new XsuaaServiceConfigurationCustom(xsuaaCredentials());
    }
    ```

3. You need to overwrite `JwtDecoder` bean so that the `AudienceValidator` checks the JWT audience not only against the client id of the primary Xsuaa service instance, but also of the binding of plan `broker`. Starting with version `2.6.2` you can implement it like that: 
    ```java
    @Bean
    @ConfigurationProperties("vcap.services.<<name of your xsuaa instance of plan broker>>.credentials")
    public XsuaaCredentials brokerCredentials() {
        return new XsuaaCredentials(); // secondary Xsuaa service binding, e.g. broker
    }
   
    @Bean
    public JwtDecoder getJwtDecoder() {
       XsuaaCredentials brokerXsuaaCredentials = brokerCredentials();
   
       XsuaaAudienceValidator customAudienceValidator = new XsuaaAudienceValidator(customXsuaaConfig());
       // customAudienceValidator.configureAnotherXsuaaInstance("test3!b1", "sb-clone1!b22|test3!b1");
       customAudienceValidator.configureAnotherXsuaaInstance(brokerXsuaaCredentials.getXsAppName(), brokerXsuaaCredentials.getClientId());
       return new XsuaaJwtDecoderBuilder(customXsuaaConfig()).withTokenValidators(customAudienceValidator).build();
    }
    ```
 4. For authorization checks you can't perform any longer "local scope checks", as same scope names might be specified in context of different XSUAA service instances. That means you have to compare scope as it is given with the access token (`scope` claim) including the `xsappname` prefix. So, make sure that `TokenAuthenticationConverter` is NOT configured to check for local scopes (`setLocalScopeAsAuthorities(false)`)! In this case configure the HttpSecurity with an `antMatcher` for local scope "Read" as following:<br>  
    ```
 	.requestMatchers("/v1/sayHello").hasAuthority(customXsuaaConfig().getAppId() + '.' + "Read")
    ```
            

## Fetch data from token

You may have code parts that requests information from the access token using `XSUserInfo userInfo = SecurityContext.getUserInfo()`, like the user's name, its tenant, and so on. So, look up your code to find its usage, for example:

```java
import com.sap.xs2.security.container.SecurityContext;
import com.sap.xs2.security.container.UserInfo;
import com.sap.xs2.security.container.UserInfoException;

try {
	XSUserInfo userInfo = SecurityContext.getUserInfo();
	String logonName = userInfo.getLogonName();
} catch (UserInfoException e) {
	// handle exception
}
```
and replace this with
```java
import com.sap.cloud.security.xsuaa.token.SpringSecurityContext;
import com.sap.cloud.security.xsuaa.token.Token;

Token token = SpringSecurityContext.getToken(); // throws AccessDeniedException
```

> Note :one:: There is no `UserInfo` anymore. To obtain the token from the thread local storage, you
have to use Spring's Security Context managed by the `SecurityContextHolder`. This is explained in detailed in the [usage section](/spring-xsuaa#usage).

> Note :two:: In case you have used formerly `Principal.getName()` be aware that `spring-xsuaa` returns a user name or client id in the following format:
> - `user/<origin>/<logonName>`
> - `client/<clientid>`
> See also Github issue [#399](https://github.com/SAP/cloud-security-services-integration-library/issues/399).


### Exception Handling
Unlike `XSUserInfo` interface there is no `XSUserInfoException` raised, in case the token does not contain the requested claim. You can check the interface, whether it can also return a `Nullable`. Then you can either perform a null check or check in advance, whether the claim is provided as part of the token, e.g. `Token.hasClaim(TokenClaims.CLAIM_CLIENT_ID)`.

### Special `XSUserInfo` methods
The `XSUserInfo` interface provides some special methods that are not available in
the `com.sap.cloud.security.xsuaa.token.Token`.

See the following table for methods that are not available anymore and workarounds.


| XSUserInfo method       | Workaround in `spring.xsuaa`                                                                                      |
|-------------------------|--------------------------------------------------------------------------------------------------|
| `checkLocalScope`       | Adapt the default behaviour of `TokenAuthenticationConverter.setLocalScopeAsAuthorities(true)` to let `getAuthorities` return local scopes. E.g. `token.getAuthorities().contains(new SimpleGrantedAuthority("Display"))`|
| `checkScope`            | Use `getScopes` and check if the scope is contained.|
| `getAttribute`          | Use `getXSUserAttribute`.                                                                        |
| `getDBToken`            | Not implemented.                                                                                 |
| `getHdbToken`           | Not implemented.                                                                                 |
| `getIdentityZone`       | Use `getZoneId` to get the tenant GUID or use `getSubaccountId` to get subaccount id, e.g. to provide it to the metering API.|
| `getJsonValue`          | Use `containsClaim` and `getClaimAsString`. See section [XsuaaToken](#xsuaatoken).               |
| `getSystemAttribute`    | This extracts data from `xs.system.attributes` claim. See section [XsuaaToken](#xsuaatoken).     |
| `getToken`              | Not implemented.                                                                                 |
| `hasAttributes`         | Use `getXSUserAttribute` and check of the attribute is available.                                |
| `isInForeignMode`       | Not implemented.                                                                                 |
| `requestToken`          | Deprecated in favor of [XsuaaTokenFlows](https://github.com/SAP/cloud-security-services-integration-library/blob/master/token-client/src/main/java/com/sap/cloud/security/xsuaa/tokenflows/XsuaaTokenFlows.java) which is provided with [token-client](/token-client) library. You can find a  migration guide [here](/token-client/Migration_XSUserInfoRequestToken.md).
| `requestTokenForClient` | Deprecated in favor of [XsuaaTokenFlows](https://github.com/SAP/cloud-security-services-integration-library/blob/master/token-client/src/main/java/com/sap/cloud/security/xsuaa/tokenflows/XsuaaTokenFlows.java) which is provided with [token-client](/token-client) library. You can find a  migration guide [here](/token-client/Migration_XSUserInfoRequestToken.md).


### XsuaaToken
The runtime type of `Token` is `XsuaaToken`. `XsuaaToken` provides additional
methods that can be used to extract data from the token since it is a subclass of
`org.springframework.security.oauth2.jwt.Jwt`. So you can for example read
claims with `getClaim` or check for claims with `containsClaim`. See the
[spring documentation](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/jwt/Jwt.html)
for more details.

## Testing
In your unit test you might want to generate jwt tokens and have them validated. The new
[java-security-test](/java-security-test) library provides it's own `JwtGenerator`. This can be embedded using the `SecurityTestRule` in Junit 4. See the following snippet as example:

```java
@ClassRule
public static SecurityTestRule securityTestRule =
	SecurityTestRule.getInstance(Service.XSUAA)
		.setKeys("/publicKey.txt", "/privateKey.txt");
```

Using the `SecurityTestRule` you can use a pre configured `JwtGenerator` to create JWT tokens with custom scopes for your tests. It configures the JwtGenerator in such a way that **it uses the public key from the [`publicKey.txt`](/java-security-test/src/main/resources) file to sign the token.**

```java
String jwt = securityTestRule.getPreconfiguredJwtGenerator()
    .withAppId(SecurityTestRule.DEFAULT_APP_ID)
    .withLocalScopes("Display", "Update")
    .createToken()
    .getTokenValue();
```

See the [java-security-test documentation](/java-security-test) for more details, also on how to leverage JUnit 5 extensions.

### Enable local testing
For local testing you might need to provide custom `VCAP_SERVICES` before you run the application. 
The new security library requires the following key value pairs in the `VCAP_SERVICES`
under `xsuaa/credentials` for jwt validation:
- `"uaadomain" : "localhost"`
- `"verificationkey" : "<public key your jwt token is signed with>"`

Before calling the service you need to provide a digitally signed JWT token to simulate that you are an authenticated user. 
- Therefore simply set a breakpoint in `JwtGenerator.createToken()` and run your `JUnit` tests to fetch the value of `jwt` from there. In that case you can use the publicKey from `java-security-test`, like its done [here](/samples/localEnvironmentSetup.sh).

Now you can test the service manually in the browser using the `Postman` chrome plugin and check whether the secured functions can be accessed when providing a valid generated Jwt Token.

## Things to check after migration 
When your code compiles again you should first check that all your unit tests are running again. If you can test your
application locally make sure that it is still working and finally test the application in cloud foundry.


## Issues
In case you face issues to apply the migration steps check this [troubleshooting](README.md#troubleshooting) for known issues and how to file the issue.

## Samples
- [cloud-bulletinboard-ads](https://github.com/SAP-samples/cloud-bulletinboard-ads/tree/solution-24-Make-App-Secure-Spring5)
- [spring-security-xsuaa usage sample](https://github.com/SAP/cloud-security-services-integration-library/tree/master/samples/spring-security-xsuaa-usage)

## Further References
- [spring-xsuaa documentation](/spring-xsuaa/README.md)
