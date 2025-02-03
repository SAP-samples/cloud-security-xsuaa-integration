# Migration Guide for Applications that use Spring Security and java-container-security

This migration guide is a step-by-step guide explaining how to replace the following SAP-internal Java Container Security Client libraries
- com.sap.xs2.security:java-container-security
- com.sap.cloud.security.xsuaa:java-container-security  

with this open-source version.

## Prerequisite
**Please note, that as of now, this Migration Guide is NOT intended for applications using SAP Java Buildpack.**   
You're using the SAP Java Buildpack, if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

This [documentation](Migration_SAPJavaBuildpackProjects.md) describes the setup when using SAP Java Buildpack.

## :bulb: Deprecation Notice

The Spring Security OAuth project is deprecated. The latest OAuth 2.0 support is provided by Spring Security. See the [OAuth 2.0 Migration Guide](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide) for further details.

The `java-container-security` as well as the `SAPOfflineTokenServicesCloud` provided as part of the current solution bases on `org.springframework.security.oauth:spring-security-oauth2` which is deprecated. In case of Spring-Boot application you may want to follow this [Migration Guide](/spring-xsuaa/Migration_JavaContainerSecurityProjects.md).


## Maven Dependencies
To use the new [java-security](/java-security) client library the dependencies declared in maven `pom.xml` need to be updated.

First make sure you have the following dependencies defined in your pom.xml:

```xml
<!-- take the latest spring-security dependencies -->
<!-- Spring deprecates it as it gets replaced with libs of groupId "org.springframework.security" -->
<dependency>
  <groupId>org.springframework.security.oauth</groupId>
  <artifactId>spring-security-oauth2</artifactId>
  <version>2.4.1.RELEASE</version> <!-- chose the latest from maven repository -->
</dependency>

<!-- new java-security dependencies -->
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>api</artifactId>
  <version>2.13.7</version>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security</groupId>
  <artifactId>java-security</artifactId>
  <version>2.13.7</version>
</dependency>

<!-- new java-security dependencies for unit tests -->
<dependency>
  <groupId>com.sap.cloud.security</groupId>
  <artifactId>java-security-test</artifactId>
  <version>2.13.7</version>
  <scope>test</scope>
</dependency>
```

Now you are ready to **remove** the **`java-container-security`** client library by deleting the following dependencies from the pom.xml:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.xs2.security | java-container-security
com.sap.xs2.security | api
com.sap.cloud.security.xssec | api 
com.sap.cloud.security.xsuaa | java-container-security-api
com.sap.cloud.security.xsuaa | java-container-security

Make sure that you do not refer to any other sap security library with group-id `com.sap.security` or `com.sap.security.nw.sso.*`. 

## Configuration changes
After the dependencies have been changed, the spring security configuration needs some adjustments as well.

If your security configuration was using the `SAPOfflineTokenServicesCloud` class from the `java-container-security` library,
you need to change it slightly to use the `SAPOfflineTokenServicesCloud` adapter class from the new library.

> Note: There is no replacement for `SAPPropertyPlaceholderConfigurer` as you can always parameterize the `SAPOfflineTokenServicesCloud` bean with your `OAuth2ServiceConfiguration`.

### Code-based

For example see the following snippet on how to instantiate the `SAPOfflineTokenServicesCloud`. 

```java
@Bean
@Profile("cloud")
protected SAPOfflineTokenServicesCloud offlineTokenServices() {
	return new SAPOfflineTokenServicesCloud(
				Environments.getCurrent().getXsuaaConfiguration(), //optional
				new RestTemplate())                                //optional
			.setLocalScopeAsAuthorities(true);                         //optional
}
```
You might need to fix your java imports to get rid of the old import for the `SAPOfflineTokenServicesCloud` class.

### XML-based
As you may have updated the 

In case of XML-based Spring (Security) configuration you need to replace your current `SAPOfflineTokenServicesCloud` bean definition with that:

```xml
<bean id="offlineTokenServices"
         class="com.sap.cloud.security.adapter.spring.SAPOfflineTokenServicesCloud">
		<property name="localScopeAsAuthorities" value="true" />
</bean>
```

With `localScopeAsAuthorities` you can perform spring scope checks without referring to the XS application name (application id), e.g. `myapp!t1234`. For example:

Or
```java
...
.authorizeRequests()
	.antMatchers(POST, "/api/v1/ads/**").access("#oauth2.hasScopeMatching('Update')") //instead of '${xs.appname}.Update'
```


```xml
<sec:intercept-url pattern="/rest/addressbook/deletedata" access="#oauth2.hasScope('Delete')" method="GET" />
```

### SAP_JWT_TRUST_ACL obsolete
There is no need to configure `SAP_JWT_TRUST_ACL` within your deployment descriptor such as `manifest.yml`. 
Instead the Xsuaa service instance adds audiences to the issued JSON Web Token (JWT) as part of the `aud` claim.

Whether the token is issued for your application or not is now validated by the [`JwtAudienceValidator`](/java-security/src/main/java/com/sap/cloud/security/token/validation/validators/JwtAudienceValidator.java).

This comes with a change regarding scopes. For a business application A that wants to call an application B, it's now mandatory that the application B grants at least one scope to the calling business application A. You can grant scopes with the `xs-security.json` file. For additional information, refer to the [Application Security Descriptor Configuration Syntax](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html), specifically the sections [referencing the application](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html#loio517895a9612241259d6941dbf9ad81cb__section_fm2_wsk_pdb) and [authorities](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html#loio517895a9612241259d6941dbf9ad81cb__section_d1m_1nq_zy). 

## Fetch basic infos from Token
You may have code parts that requests information from the access token, like the user's name, its tenant, and so on. So, look up your code to find its usage.


```java
import com.sap.xs2.security.container.SecurityContext;
import com.sap.xs2.security.container.UserInfo;
import com.sap.xs2.security.container.UserInfoException;


try {
	UserInfo userInfo = SecurityContext.getUserInfo();
	String logonName = userInfo.getLogonName();
} catch (UserInfoException e) {
	// handle exception
}

```

This can be easily replaced with the `Token` or `XsuaaToken` Api.

```java
import com.sap.cloud.security.token.*;

AccessToken token = SecurityContext.getAccessToken();
String logonName = token.getClaimAsString(TokenClaims.USER_NAME);
boolean hasDisplayScope = token.hasLocalScope("Display");	
GrantType grantType = token.getGrantType();
```

> Note, that no `XSUserInfoException` is raised, in case the token does not contain the requested claim.

## Fetch further `XSUserInfo` infos from Token
When you're done with the first part and need further information from the token you can use `XSUserInfoAdapter` in order to access the remaining methods exposed by the [`XSUserInfo`](/api/src/main/java/com/sap/xsa/security/container/XSUserInfo.java) Interface.

```java
try {
	XSUserInfo userInfo = new XSUserInfoAdapter(token);
	String dbToken = userInfo.getHdbToken();
} catch (XSUserInfoException e) {
	// handle exception
}
```

## Test Code Changes

### Security configuration for tests
If you want to overwrite the service configuration of the `SAPOfflineTokenServicesCloud` for your test, you can do so by
using some test constants provided by the test library. The following snippet shows how to do that:
```java 
import static com.sap.cloud.security.config.cf.CFConstants.*;

@Configuration
public class TestSecurityConfig {
	@Bean
	@Primary
	public SAPOfflineTokenServicesCloud sapOfflineTokenServices() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId(SecurityTestRule.DEFAULT_CLIENT_ID)
				.withProperty(CFConstants.XSUAA.APP_ID, SecurityTestRule.DEFAULT_APP_ID)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, SecurityTestRule.DEFAULT_DOMAIN)
				.build();

		return new SAPOfflineTokenServicesCloud(configuration).setLocalScopeAsAuthorities(true);
	}
}
```

### Unit testing 
In your unit test you might want to generate jwt tokens and have them validated. The [java-security-test](/java-security-test) library provides it's own `JwtGenerator`.  This can be embedded using the 
`SecurityTestRule`. See the following snippet as example: 

```java
@ClassRule
public static SecurityTestRule securityTestRule =
	SecurityTestRule.getInstance(Service.XSUAA)
		.setKeys("/publicKey.txt", "/privateKey.txt");
```

Using the `SecurityTestRule` you can use a preconfigured `JwtGenerator` to create JWT tokens with custom scopes for your tests. It configures the JwtGenerator in such a way that **it uses the public key from the [`publicKey.txt`](/java-security-test/src/main/resources) file to sign the token.**

```java
static final String XSAPPNAME = SecurityTestRule.DEFAULT_APP_ID;
static final String DISPLAY_SCOPE = XSAPPNAME + ".Display";
static final String UPDATE_SCOPE = XSAPPNAME + ".Update";

String jwt = securityTestRule.getPreconfiguredJwtGenerator()
    .withScopes(DISPLAY_SCOPE, UPDATE_SCOPE)
    .createToken()
    .getTokenValue();

```
Make sure, that your JUnit tests are running.

The `java-security-test` library provides also JUnit 5 support as described [here](/java-security-test).

## Enable local testing
For local testing you might need to provide custom `VCAP_SERVICES` before you run the application. 
The new security library requires the following key value pairs in the `VCAP_SERVICES`
under `xsuaa/credentials` for jwt validation:
- `"uaadomain" : "localhost"`
- `"verificationkey" : "<public key your jwt token is signed with>"`

Before calling the service you need to provide a digitally signed JWT token to simulate that you are an authenticated user. 
- Therefore simply set a breakpoint in `JWTGenerator.createToken()` and run your `JUnit` tests to fetch the value of `jwt` from there. 

Now you can test the service manually in the browser using the `Postman` chrome plugin and check whether the secured functions can be accessed when providing a valid generated Jwt Token.


## Things to check after migration 
When your code compiles again you should first check that all your unit tests are running again. If you can test your
application locally make sure that it is still working and finally test the application in cloud foundry.

## Troubleshoot

### Issues with XML schema declarations
If you get errors in the aplication log similar to this one

```
Configuration problem: You cannot use a spring-security-4.0.xsd or spring-security-4.1.xsd schema with Spring Security 4.2. Please update your schema declarations to the 4.2 schema. Offending resource: ServletContext resource [/WEB-INF/spring-security.xml]
```

You can fix this by removing the Spring versions of the schema declaration in the file `/WEB-INF/spring-security.xml`. Without explicit versions set, the latest version will be used.

```
xsi:schemaLocation="http://www.springframework.org/schema/security/oauth2
		    http://www.springframework.org/schema/security/spring-security-oauth2.xsd
		    http://www.springframework.org/schema/security
		    http://www.springframework.org/schema/security/spring-security.xsd
		    http://www.springframework.org/schema/beans
		    http://www.springframework.org/schema/beans/spring-beans.xsd
```

If you get an `org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException` like this:

```
org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException: Line XX in XML document from ServletContext resource [/WEB-INF/spring-security.xml] is invalid; 
nested exception is org.xml.sax.SAXParseException; lineNumber: 51; columnNumber: 118; cvc-complex-type.2.4.c: 
The matching wildcard is strict, but no declaration can be found for element 'oauth:resource-server'.
```

You can fix this by changing the schema location to `https` for `oauth2` as below in the `/WEB-INF/spring-security.xml`. With this change, the local jar is available and solves the issue of server trying to connect to get the jar and fails due to some restrictions.

```
xsi:schemaLocation="http://www.springframework.org/schema/security/oauth2
https://www.springframework.org/schema/security/spring-security-oauth2.xsd
```

### HTTP 403 unauthorized errors although token contains scope

If you use `SAPOfflineTokenServicesCloud` together with `HttpServlet` scope checks (e.g. `httpRequest.isUserInRole`), you might get 403 unauthorized errors even though the token contains the correct scope. This can happen if *automatic ROLE_prefixing* is enabled in Spring and the roles of the token do not have a `ROLE_` prefix. To fix this problem you can disable the automatic ROLE_prefixing in Spring. This is described [here](https://docs.spring.io/spring-security/site/migrate/current/3-to-4/html5/migrate-3-to-4-jc.html#m3to4-role-prefixing). Anther way to fix this problem is to manually prefix all scopes with `ROLE_`. After that your scope checks should work as expected.


## Issues
In case you face issues to apply the migration steps check this [troubleshoot](README.md#troubleshoot) for known issues and how to file the issue.

