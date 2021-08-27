# XSUAA Security Test Library

## Deprecation Note
**This is in maintaince mode, don't use it for new projects!**
Instead, make use of [`java-security-test`](/java-security-test) testing library. Have a look at the [spring-security-xsuaa-usage](/samples/spring-security-xsuaa-usage) as usage reference.

## Description
This library enhances the `spring-xsuaa` project.
This includes for example a `JwtGenerator` that generates JSON Web Tokens (JWT) that can be used for JUnit tests, as well as for local testing.

 `JwtGenerator` provides these helper functions to you:
 1. load an encoded **Jwt token from file** or
 1. create a **Jwt token from a template file**, whereas some placeholders gets replaced
 1. create a **basic Jwt token** that has minimal set of preconfigured claims, **which can be enhanced** with `scopes` and `xs.user.attributes` claims and `keyId` header.
 1. create an **individual Jwt token** based on a set of claims using Nimbus JOSE + JWT [`JWTClaimsSet.Builder()`](http://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/6.5.1).

 All of them are returned as [`Jwt`](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/jwt/Jwt.html), which offers you a `getTokenValue()` method that returns the encoded and signed Jwt token. You need to prefix this one with `Bearer ` in case you like to provide it via `Authorization` header to your application.

 > In most cases the Jwt gets Base64 encoded and signed with this [private key](src/main/resources/spring-xsuaa-privateKey.txt).


## Requirements
- Java 8
- maven 3.3.9 or later
- Spring Boot 2.1 and later

## Configuration

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>spring-xsuaa-test</artifactId>
    <version>2.10.6</version>
    <scope>test</scope>
</dependency>

<!-- only if not already included -->
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
    <scope>test</scope>
</dependency>
```

## Usage
Find examples on how to use the `JwtGenerator` [here](src/test/java/com/sap/cloud/security/xsuaa/test/JwtGeneratorTest.java).

### Troubleshoot

#### Jwt validation fails because of missing audience
```
DEBUG .o.s.r.w.BearerTokenAuthenticationFilter : Authentication request for failed: org.springframework.security.oauth2.core.OAuth2AuthenticationException: An error occurred while attempting to decode the Jwt: Missing audience
```

This can have different causes. The first one is obvious, your JWT token lacks of `aud` claim which contains the application names of the scopes. Make sure, that you've configured the `JwtGenerator` appropriately. Secondly make sure, that the xs application name, your scopes are prefixed with, is provided either via `VCAP_SERVICES` system environment variable or via properties e.g. `xsuaa.xsappname=xsapplication!t895`
