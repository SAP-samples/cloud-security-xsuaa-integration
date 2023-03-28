/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples;

import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.test.extension.SecurityTestExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletIntegrationTest {

	@RegisterExtension
	static SecurityTestExtension extension = SecurityTestExtension.forService(XSUAA)
			.useApplicationServer()
			.addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT)
			.addApplicationServlet(HelloJavaServletScopeProtected.class, HelloJavaServletScopeProtected.ENDPOINT);

	private static CloseableHttpClient httpClient;

	@BeforeAll
	static void setup() {
		httpClient = HttpClients.createDefault();
	}

	@AfterEach
	void clearSecurityContext() {
		SecurityContext.clear();
	}

	@AfterAll
	static void tearDown() throws IOException {
		httpClient.close();
	}

	@Test
	void requestWithoutAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(null);
		int statusCode = httpClient.execute(request, HttpResponse::getCode);
		assertThat(statusCode).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
	}

	@Test
	void requestWithEmptyAuthorizationHeader_unauthenticated() throws Exception {
		HttpGet request = createGetRequest("");
		int statusCode = httpClient.execute(request, HttpResponse::getCode);
		assertThat(statusCode).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
	}

	@Test
	void requestWithValidTokenWithoutScopes_unauthorized() throws IOException {
		String jwt = extension.getContext().getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.createToken()
				.getTokenValue();
		HttpGet request = createGetRequest(jwt, HelloJavaServletScopeProtected.ENDPOINT);
		int statusCode = httpClient.execute(request, HttpResponse::getCode);
		assertThat(statusCode).isEqualTo(HttpStatus.SC_FORBIDDEN); // 403
	}

	@Test
	void requestWithValidToken_ok() throws IOException {
		String jwt = extension.getContext().getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.withScopes(SecurityTestRule.DEFAULT_APP_ID + '.' + "Read")
				.withClaimValue(TokenClaims.EMAIL, "tester@mail.com")
				.createToken()
				.getTokenValue();
		HttpGet request = createGetRequest(jwt);

		String responseBody = httpClient.execute(request, response -> {
			assertThat(response.getCode()).isEqualTo(HttpStatus.SC_OK); // 200

			return EntityUtils.toString(response.getEntity());
		});

		assertThat(responseBody)
				.contains("You ('tester@mail.com') can access the application with the following scopes: '[xsapp!t0815.Read]'.");
		assertThat(responseBody)
				.contains("Having scope '$XSAPPNAME.Read'? true");
	}

	private HttpGet createGetRequest(String accessToken) {
		return createGetRequest(accessToken, HelloJavaServlet.ENDPOINT);
	}

	private HttpGet createGetRequest(String accessToken, String endpoint) {
		HttpGet httpGet = new HttpGet(extension.getContext().getApplicationServerUri() + endpoint);
		if(accessToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
		}
		return httpGet;
	}
}