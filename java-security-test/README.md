# SAP BTP Java Security Test Library

The project `java-security-test` offers utility to write JUnit tests of applications secured with [java-security](../java-security), [spring-security](../spring-security) or [spring-xsuaa](../spring-xsuaa) without access to a real identity service instance.
To this end, it starts a [WireMock](https://wiremock.org/) server running on `localhost` that is pre-configured with stubbed responses, e.g. for the JWKS or OIDC endpoints.
This server can be used as a mocked Identity or Xsuaa service instead of an actual service instance. It can be used to test both Spring (Boot) and Java EE applications.

To test the security layers of the application, custom JSON Web Tokens (JWT) with the chosen properties and claims can be generated with a [JwtGenerator](./src/main/java/com/sap/cloud/security/test/JwtGenerator.java).
The tokens issued by JwtGenerator are signed with a key that fits the stubbed JWKS provided by the mock server to validate the signature.

Spring Boot applications can use the provided utility for example in the context of a `WebMvcTest`.\
For Java EE applications, an optional [Jetty application server](#jetty-application-server) can be started.
It is pre-configured with a security filter that only accepts valid tokens. Furthermore, it can be configured to mount both servlets and servet filters that require testing.

## Requirements
- Java 17
- maven 3.3.9 or later
- JUnit 4 or 5

> If you use spring-boot-starter-test, you might be facing json classpath issues. See the [Troubleshooting](#Troubleshooting)
> section for more information.

1. [Setup](#setup)
    + [Maven Dependencies](#maven-dependencies)
    + [Java EE](#java-ee)
    + [Spring Boot](#spring-boot)
2. [Usage](#usage)
    + [JUnit 4 Test](#junit-4-test)
    + [JUnit 5 Test](#junit-5-test)
        - [(Option A) Use XsuaaExtension or IasExtension](#-option-a--use-xsuaaextension-or-iasextension)
        - [(Option B) Configure a custom SecurityTestExtension](#-option-b--configure-a-custom-securitytestextension)
    + [Jwt Generation](#jwt-generation)
    + [Jetty Application Server](#jetty-application-server)
3. [Troubleshooting](#troubleshooting)
4. [Samples](#samples)

## Setup

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
   <artifactId>java-security-test</artifactId>
   <version>3.5.5</version>
   <scope>test</scope>
</dependency>
```

### Java EE

To make use of the provided `WireMock` server to test Java EE servlets and servlet filters, we provide an embedded [Jetty application server](#jetty-application-server) that can mount them.
The application server is already pre-configured to accept only requests including tokens from `JwtGenerator`.

### Spring Boot

If you are using Spring Boot Auto-configuration to test Spring controllers, you need to configure the service configuration to target the `WireMock` server.
To do so, provide a service configuration for testing via Spring properties that targets the stubbed `WireMock` server as identity service.
Then, you can test your controllers as usual, for instance in the context of a `WebMvcTest` (see [spring-security-hybrid-usage](../samples/spring-security-hybrid-usage/src/test/java/sample/spring/security/TestControllerTest.java) for an example).

There are different ways to configure Spring properties for testing, e.g. dedicated test profiles or property files.
Another alternative is to define a TestPropertySource programmatically to inject the properties into a specific unit test.\
The following example uses TestPropertySource to configure `java-security` for an XSUAA `WireMock` identity service.

```java
import static com.sap.cloud.security.test.SecurityTest.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = { 
		"xsuaa.uaadomain=" + DEFAULT_UAA_DOMAIN, 
		"xsuaa.xsappname=" + DEFAULT_APP_ID,
		"xsuaa.clientid=" + DEFAULT_CLIENT_ID })
@ExtendWith(XsuaaExtension.class)
public class HelloSpringTest {

	@Test
	public void sayHello(SecurityTestContext context) {
		String jwt = context.getPreconfiguredJwtGenerator()
						.withLocalScopes("Read")
						.createToken().getTokenValue();
		// ... call endpoint with Authorization header "Bearer <jwt>" ...
	}
}
```

## Usage
There are multiple [Samples](#Samples) showing how to utilize this project for different scenarios.

A typical use involves setting up either a [SecurityTestRule](./src/main/java/com/sap/cloud/security/test/SecurityTestRule.java) (JUnit 4) or [SecurityTestExtension](./src/main/java/com/sap/cloud/security/test/extension/SecurityTestExtension.java) (JUnit 5) before the tests.
These classes are decorators around a [SecurityTest](./src/main/java/com/sap/cloud/security/test/SecurityTest.java) that add lifecycle methods for integration in JUnit runners.
They automatically start the `WireMock` server and in addition, the optional [Jetty application server](#jetty-application-server) if configured to do so.

Besides configuration methods, e.g. for the port of the servers or the application server setup, they offer access to a [JwtGenerator](#jwt-generation).
It can be used to generate tokens with custom properties and claims, that, together with the `WireMock` server allow offline testing of the application's endpoints.

### JUnit 4 Test
Set up a [SecurityTestRule](./src/main/java/com/sap/cloud/security/test/SecurityTestRule.java) with the different configuration methods it provides. It acts as an `ExternalResource` that starts the `WireMock` server and optionally a [Jetty servlet container](#jetty-application-server) before the tests.
> :exclamation: Make sure to call `tearDown` after the tests to stop the servers and free resources.
> :exclamation: Mplease consider migrating to JUnit5 and use an Extension instead of a rule.

The following code is an example how to mount a Servlet on the embedded Jetty servet container and test access to its endpoint with a valid token generated by [JwtGenerator](#jwt-generation).

```java
public class HelloJavaServletTest {
    
    @ClassRule
    public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA) // or Service.IAS
            .useApplicationServer() // start optional Jetty application server
            .addApplicationServlet(HelloJavaServlet.class, "/hello-world");  // manually mount servlet on application server
    
    @After
    public void tearDown() {
                SecurityContext.tearDown(); // shutdown servers etc.
    }

    /** Tests access to /hello-world with a valid JWT with scope Read. */
    @Test
    public void testAccessWithReadScope() {
                String jwt = rule.getPreconfiguredJwtGenerator()
				.withScopes("openid")
				.withLocalScopes("Read") // = SecurityTestRule.DEFAULT_APP_ID + ".Read"
				.createToken()
				.getTokenValue();

        // ... call /hello-world with 'Authorization' header "Bearer <jwt>" and expect status code 200 ...		
    }
}
```

### JUnit 5 Test
Set up a [SecurityTestExtension](./src/main/java/com/sap/cloud/security/test/extension/SecurityTestExtension.java) with the different configuration methods it provides.
It starts the `WireMock` server and optionally a [Jetty servlet container](#jetty-application-server) before the tests.

#### (Option A) Use XsuaaExtension or IasExtension

The easiest way to set up, is to use either  `XsuaaExtension` or `IasExtension`.
They both start the `WireMock` server in their `BeforeAllCallback` lifecycle method and stop the running server(s) in `AfterAllCallback`.
Their default settings are usually enough for application testing with custom generated tokens.
They do, however, not start the Jetty application server.

```java
@ExtendWith(XsuaaExtension.class) // or IasExtension.class
public class HelloJavaTest {

    @Test
    public void testReadAccess(SecurityTestContext context) {
                String jwt = context.getPreconfiguredJwtGenerator()
						.withLocalScopes("Read")
						.createToken().getTokenValue();
        
        // ... call endpoint with 'Authorization' header "Bearer <jwt>" ...			
    }
}
```

#### (Option B) Configure a custom SecurityTestExtension
In case you need to manually configure the `SecurityTestExtension`, e.g. to start the optional Jetty application container, create an extension via `SecurityTestExtension#forService` and register it as JUnit extension, by using the `@RegisterExtension` annotation.

> :warning: Please note, that `@RegisterExtension` for `SecurityTestExtension` can NOT be used in combination with `@TestInstance(TestInstance.Lifecycle.PER_CLASS)`!
```java
public class HelloJavaServletTest {
    @RegisterExtension
    static SecurityTestExtension extension = SecurityTestExtension.forService(Service.XSUAA) // or Service.IAS
            .setPort(4711) // sets the port of the identity service mock server
            .useApplicationServer() // start optional Jetty application server
            .addApplicationServlet(HelloJavaServlet.class, "/hello-world");  // manually mount servlet on application server

    @Test
    public void sayHello() {
                String jwt = rule.getPreconfiguredJwtGenerator()
                .withScopes("openid")
                .withLocalScopes("Read") // = SecurityTestRule.DEFAULT_APP_ID + ".Read"
                .createToken()
                .getTokenValue();

        // ... call /hello-world with 'Authorization' header "Bearer <jwt>" and expect status code 200 ...
    }
}
```

### Jwt Generation
Using `JwtGenerator` you can create custom JWTs in the form of [`Token`](../java-api/src/main/java/com/sap/cloud/security/token/Token.java) objects.
> To use these JWTs in your request, set the 'Authorization' header of the request to "Bearer &lt;jwt&gt;", where &lt;jwt&gt; is the value of `Token#getTokenValue'.

By default, the tokens are signed with a random RSA private key (starting with version `2.8.1`) whose public key is included in the JWKS endpoint of the `WireMock` server.
This means, the signature validation of these tokens will succeed if you set up your service configuration to the `WireMock` server.

The tokens can be constructed with custom claim values and other properties, e.g. via `JwtGenerator#withClaimValue`, to test the application in different security contexts.
For instance, you can specify a custom `azp` as shown in the code example below.


```java
Token token = JwtGenerator.getInstance(Service.XSUAA, "client-id")
                                .withHeaderParameter(TokenHeader.KEY_ID, "key-id") // optional
                                .withClaimValue(TokenClaims.XSUAA.AUTHORIZATION_PARTY, azp) // optional
                                .createToken();

String authorizationHeaderValue = 'Bearer ' + token.getTokenValue();
```

### Jetty Application Server
Optionally, you can instruct the JUnit Rule/Extension via `useApplicationServer` to start an embedded Jetty servlet container that comes secured with an [TokenAuthenticator](../java-api/src/main/java/com/sap/cloud/security/servlet/TokenAuthenticator.java).
The authenticator blocks requests with HTTP `401` (Unauthenticated) that do not contain a JWT that is valid for the mocked service configuration.
Additional filters can be added via `addApplicationServletFilter`, e.g. to filter specific routes based on roles and/or scopes.

Servlets mapped via a web.xml configuration will automatically be mounted by the application server.
However, servlets mapped via annotations, are not mounted automatically.
To manually mount servlets on the application server, you can use `addApplicationServlet`.

## Troubleshooting

This module requires the [JSON-Java](https://github.com/stleary/JSON-java) library.
If you have classpath related  issues involving JSON you should take a look at the
[Troubleshooting JSON class path issues](../docs/Troubleshooting_JsonClasspathIssues.md) document.

## Samples
The `java-security-test` library is used in [java-security-it](../java-security-it) as well as the following samples:
- [java-security-usage](../samples/java-security-usage)
- [java-security-usage-ias](../samples/java-security-usage-ias)
- [spring-security-hybrid-usage](../samples/spring-security-hybrid-usage)
