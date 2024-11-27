/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SecurityContextTest {

	private static final Token TOKEN = new MockTokenBuilder().build();
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();

	@BeforeEach
	public void setUp() {
		SecurityContext.clear();
	}

	@Test
	public void setTokenAndRetrieve_NullToken() {
		SecurityContext.setToken(TOKEN);
		SecurityContext.setToken(null);
		assertThat(SecurityContext.getToken()).isNull();
	}

	@Test
	public void getInitialToken_isNull() {
		Token token = SecurityContext.getToken();

		assertThat(token).isNull();
	}

	@Test
	public void setTokenAndGet() {
		SecurityContext.setToken(TOKEN);
		assertThat(SecurityContext.getToken()).isEqualTo(TOKEN);
	}

	@Test
	public void clear_removesToken() {
		SecurityContext.setToken(TOKEN);
		SecurityContext.clear();

		assertThat(SecurityContext.getToken()).isNull();
	}

	@Test
	public void tokenNotAvailableInDifferentThread() throws ExecutionException, InterruptedException {
		SecurityContext.setToken(TOKEN);

		Future<Token> tokenInOtherThread = executorService.submit(() -> SecurityContext.getToken());

		assertThat(tokenInOtherThread.get()).isNull();
	}

	@Test
	public void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		SecurityContext.setToken(TOKEN);

		executorService.submit(() -> SecurityContext.clear()).get(); // run and await other thread

		assertThat(SecurityContext.getToken()).isEqualTo(TOKEN);
	}

	@Test
	public void getAccessTokenReturnsNullIfTokenDoesNotImplementInterface() {
		SecurityContext.setToken(TOKEN);
		assertThat(SecurityContext.getAccessToken()).isNull();
	}

	@Test
	public void getAccessTokenReturns() throws IOException {
		AccessToken accessToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
		SecurityContext.setToken(accessToken);
		assertThat(SecurityContext.getAccessToken()).isEqualTo(accessToken);
	}

	@Test
	public void setGetRemoveServicePlans() {
		SecurityContext.setServicePlans("\"plan1\" , \"plan \"two\"\",\"plan3\"");
		assertThat(SecurityContext.getServicePlans()).containsExactly("plan1", "plan \"two\"", "plan3");
		SecurityContext.clearServicePlans();
		assertThat(SecurityContext.getServicePlans()).isNull();
	}
}
