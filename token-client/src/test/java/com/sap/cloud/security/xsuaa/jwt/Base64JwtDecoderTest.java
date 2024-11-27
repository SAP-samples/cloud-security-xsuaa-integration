/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.jwt;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

public class Base64JwtDecoderTest {

	private String encodedJwt = "eyJhbGciOiJIUzI1NiIsImprdSI6Imh0dHBzOi8vYWNtZS1lbnRlcnByaXNlcy5hdXRoZW50aWNhdGlvbi5leGFtcGxlLmNvbS90b2tlbl9rZXlzIiwia2lkIjoia2V5LWlkLTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJlM2MzMGUyNDc0Y2Q0NjYwOWEyNjJlZGE5ZDlkYzI2ZCIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJ6ZG4iOiJhY21lLWVudGVycHJpc2VzIn0sInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InhzLnJvbGVjb2xsZWN0aW9ucyI6W119LCJnaXZlbl9uYW1lIjoiQW5kcmVhIE1hcmlhIiwieHMudXNlci5hdHRyaWJ1dGVzIjp7fSwiZmFtaWx5X25hbWUiOiJNaWxsc2FwIiwic3ViIjoiMTIzNCIsInNjb3BlIjpbIm9wZW5pZCIsInVhYS51c2VyIl0sImNsaWVudF9pZCI6Im15LWFwcDEiLCJjaWQiOiJteS1hcHAxIiwiYXpwIjoibXktYXBwMSIsImdyYW50X3R5cGUiOiJhdXRob3JpemF0aW9uX2NvZGUiLCJ1c2VyX2lkIjoiMTIzNCIsIm9yaWdpbiI6ImxkYXAiLCJ1c2VyX25hbWUiOiJhbS5taWxsc2FwQHNhcC5jb20iLCJlbWFpbCI6ImFtLm1pbGxzYXBAc2FwLmNvbSIsImF1dGhfdGltZSI6MTU2NDc4NTcyMCwicmV2X3NpZyI6Ijg3ZTdjMDE2IiwiaWF0IjoxNTY0Nzg1NzIwLCJleHAiOjE1NjQ3ODU3MjEsImlzcyI6Imh0dHA6Ly9hY21lLWVudGVycHJpc2VzLmV4YW1wbGUuY29tL3VhYS9vYXV0aC90b2tlbiIsInppZCI6IjIzNDUiLCJhdWQiOlsibXktYXBwMSIsInVhYSIsIm9wZW5pZCJdfQ.yqEcFR3EkzVSfVo3tfxsl9kc6KtCSe75-al5cTZbzhk";

	private static final String JKU_HEADER = "http://my.jku/token_keys";
	private static final String CLIENT_ID = "clientId123";
	private static final String[] SCOPES = { "scope1", "scope2" };

	private final static Jwt TOKEN = new JwtGenerator(CLIENT_ID)
			.addScopes(SCOPES)
			.setJku(JKU_HEADER)
			.getToken();

	@Test
	public void itDecodesAnEncodedJwtString() {
		String expectedDecodedJWTPayload = "{\"jti\":\"e3c30e2474cd46609a262eda9d9dc26d\",\"ext_attr\":{\"enhancer\":\"XSUAA\",\"zdn\":\"acme-enterprises\"},\"xs.system.attributes\":{\"xs.rolecollections\":[]},\"given_name\":\"Andrea Maria\",\"xs.user.attributes\":{},\"family_name\":\"Millsap\",\"sub\":\"1234\",\"scope\":[\"openid\",\"uaa.user\"],\"client_id\":\"my-app1\",\"cid\":\"my-app1\",\"azp\":\"my-app1\",\"grant_type\":\"authorization_code\",\"user_id\":\"1234\",\"origin\":\"ldap\",\"user_name\":\"am.millsap@sap.com\",\"email\":\"am.millsap@sap.com\",\"auth_time\":1564785720,\"rev_sig\":\"87e7c016\",\"iat\":1564785720,\"exp\":1564785721,\"iss\":\"http://acme-enterprises.example.com/uaa/oauth/token\",\"zid\":\"2345\",\"aud\":[\"my-app1\",\"uaa\",\"openid\"]}";
		String expectedDecodedJWTHeader = "{\"alg\":\"HS256\",\"jku\":\"https://acme-enterprises.authentication.example.com/token_keys\",\"kid\":\"key-id-1\",\"typ\":\"JWT\"}";
		String expectedDecodedJWTSignature = "yqEcFR3EkzVSfVo3tfxsl9kc6KtCSe75-al5cTZbzhk";
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(encodedJwt);
		assertEquals(expectedDecodedJWTPayload, decodedJwt.getPayload());
		assertEquals(expectedDecodedJWTHeader, decodedJwt.getHeader());
		assertEquals(expectedDecodedJWTSignature, decodedJwt.getSignature());
	}

	@Test
	public void itThrowsIfJwtDoesNotConsistOfThreeSegments() {
		Throwable exception = assertThrows(IllegalArgumentException.class, () ->

			Base64JwtDecoder.getInstance().decode("invalid"));
		assertTrue(exception.getMessage().contains("JWT token does not consist of 'header'.'payload'.'signature'."));
	}

	@Test
	public void itAllowsEmptyPayload() {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode("header..signature");
		assertEquals("", decodedJwt.getPayload());
	}

	@Test
	public void toStringReturnsHeadersAndPayload() {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(TOKEN.getTokenValue());
		assertThat(decodedJwt.toString())
				.contains("Jwt header")
				.contains(JKU_HEADER)
				.contains("Jwt payload")
				.contains(CLIENT_ID)
				.contains(SCOPES);
	}

	@Test
	public void toStringWithInvalidTokenReturnsEmptyString() {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode("header..signature");

		assertThat(decodedJwt.toString())
				.contains("Jwt header")
				.contains("Jwt payload");

		decodedJwt = Base64JwtDecoder.getInstance().decode("..signature");

		assertThat(decodedJwt.toString())
				.contains("Jwt header")
				.contains("Jwt payload");
	}

	@Test
	public void toStringDoesNotContainSignatureNorEncodedToken() {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(TOKEN.getTokenValue());

		assertThat(decodedJwt.toString())
				.doesNotContain(decodedJwt.getSignature())
				.doesNotContain(TOKEN.getTokenValue());
	}

}
