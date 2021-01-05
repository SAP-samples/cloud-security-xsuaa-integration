package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class TokenUtilTest {

	private static String encodedIasToken;
	private static String encodedXsuaaToken;
	private static final String invalidToken = "eyJqa3UiOiJodHRwOi8vbG9jYWxob3N0OjY0MzEyL3Rva2VuX2tleXMiLCJraWQiOiJkZWZhdWx0LWtpZCIsImFsZyI6IkhTMjU2In0.eyJjbGllbnRfaWQiOiJzYi1qYXZhLWhlbGxvLXdvcmxkIiwiY2lkIjoic2ItamF2YS1oZWxsby13b3JsZCIsImF6cCI6InNiLWphdmEtaGVsbG8td29ybGQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIn0.6cACH-Z8Kr0p6prBYd2gp7nEfOJsA4OsXO_Hkj99XyU";

	@Before
	public void setup() throws IOException {
		encodedIasToken = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);
		encodedXsuaaToken = IOUtils.resourceToString("/token_xsuaa.txt", StandardCharsets.UTF_8);
	}

	@Test
	public void isXsuaaTokenFalseTest() {
		assertFalse(TokenUtil.isXsuaaToken(TokenUtil.decodeJwt(encodedIasToken)));
	}

	@Test
	public void isXsuaaTokenTrueTest() {
		assertTrue(TokenUtil.isXsuaaToken(TokenUtil.decodeJwt(encodedXsuaaToken)));
	}

	@Test
	public void isXchangeEnabledTest() {
		assertFalse(TokenUtil.isIasToXsuaaXchangeEnabled());
	}

	@Test
	public void parseXsuaaTest() {
		Jwt jwt = TokenUtil.parseJwt(TokenUtil.decodeJwt(encodedXsuaaToken));
		assertEquals(2, jwt.getHeaders().size());
		assertEquals(20, jwt.getClaims().size());
		assertEquals(jwt.getIssuedAt(), Instant.ofEpochSecond(1442912244));
		assertEquals(jwt.getExpiresAt(), Instant.ofEpochSecond(1603468794));
	}

	@Test
	public void tokenWithMissingExpClaim() {
		DecodedJwt decodedJwt = TokenUtil.decodeJwt(invalidToken);
		assertThrows(JSONException.class, () -> TokenUtil.parseJwt(decodedJwt));
	}

}