/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

public class SpringSecurityContextTest {

	private Jwt token_1;
	private Jwt token_2;

	private static final String SUBDOMAIN_1 = "subdomain-1";
	private static final String SUBDOMAIN_2 = "subdomain-2";
	private static final String CLIENT_ID = "sb-xsappname!t123";

	@BeforeEach
	public void setup() {
		token_1 = new JwtGenerator(CLIENT_ID, SUBDOMAIN_1).getToken();
		token_2 = new JwtGenerator(CLIENT_ID, SUBDOMAIN_2).getToken();
	}

	@Test // Access forbidden: not authenticated
	public void getSecurityContextRaiseAccessDeniedExceptionIfNotInitialized() {
		assertThrows(AccessDeniedException.class, () ->
			SpringSecurityContext.getToken());
	}

	@Test // Passed JwtDecoder instance must be of type 'XsuaaJwtDecoder'
	public void initSecurityContextRaiseExceptionIfNotXsuaaJwtDecoder() {
		assertThrows(IllegalArgumentException.class, () ->
			SpringSecurityContext.init(token_1.getTokenValue(), s -> token_1, new DefaultAuthoritiesExtractor()));
	}

	/**
	 * This test case spawns two parallel Threads. Each Thread uses a token and invokes SpringSecurityContext.init(...).
	 * A Token object is retrieved by the SpringSecurityContext and returned to the main Thread. On the main Thread, we
	 * assert that both Threads have been in the appropriate Tenant Context.
	 *
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	@Test
	public void setSecurityContext() throws InterruptedException, ExecutionException {

		ExecutorService executor = Executors.newFixedThreadPool(2);

		Future<Token> future_1 = executor.submit(() -> {
			initSecurityContextWithToken(token_1);
			return SpringSecurityContext.getToken();
		});
		Future<Token> future_2 = executor.submit(() -> {
			initSecurityContextWithToken(token_2);
			return SpringSecurityContext.getToken();
		});

		assertEquals(SUBDOMAIN_1, future_1.get().getSubdomain());
		assertEquals(SUBDOMAIN_1 + "-id", future_1.get().getZoneId());

		assertEquals(SUBDOMAIN_2, future_2.get().getSubdomain());
		assertEquals(SUBDOMAIN_2 + "-id", future_2.get().getZoneId());
	}

	private static void initSecurityContextWithToken(Jwt token) throws InterruptedException {
		XsuaaJwtDecoder mockXsuaaJwtDecoder = Mockito.mock(XsuaaJwtDecoder.class);
		when(mockXsuaaJwtDecoder.decode(token.getTokenValue())).thenReturn(token);

		// initialize SpringSecurityContext with provided token
		SpringSecurityContext.init(token.getTokenValue(), mockXsuaaJwtDecoder, new DefaultAuthoritiesExtractor());
	}
}
