/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import org.assertj.core.util.Maps;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Map;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class PasswordTokenFlowTest {

	private OAuth2TokenService tokenService;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private PasswordTokenFlow cut;

	@BeforeEach
	public void setUp() {
		tokenService = mock(OAuth2TokenService.class);
		endpointsProvider = mock(OAuth2ServiceEndpointsProvider.class);

		when(endpointsProvider.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT_URI);

		cut = new PasswordTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS);
	}

	@Test
	public void tokenServiceIsNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(null, endpointsProvider, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2TokenService");
	}

	@Test
	public void endpointsProviderIsNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(tokenService, null, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void clientCredentialsAreNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(tokenService, endpointsProvider, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ClientIdentity");
	}

	@Test
	public void execute_usernameIsMissing_throwsException() {
		PasswordTokenFlow passwordTokenFlow = new PasswordTokenFlow(tokenService, endpointsProvider,
				CLIENT_CREDENTIALS);
		assertThatThrownBy(() -> passwordTokenFlow.password(PASSWORD).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Username");
	}

	@Test
	public void execute_passwordIsMissing_throwsException() {
		PasswordTokenFlow passwordTokenFlow = new PasswordTokenFlow(tokenService, endpointsProvider,
				CLIENT_CREDENTIALS);
		assertThatThrownBy(() -> passwordTokenFlow.username(USERNAME).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Password");
	}

	@Test
	public void execute_returnsCorrectAccessTokenInResponse() throws Exception {
		mockValidResponse();

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getAccessToken()).isEqualTo(ACCESS_TOKEN);
	}

	@Test
	public void execute_ReturnsDifferentAccessTokenInResponse() throws Exception {
		String otherAccessToken = "qwertyqwerty";
		mockValidResponse(otherAccessToken);

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getAccessToken()).isEqualTo(otherAccessToken);
	}

	@Test
	public void execute_ReturnsRefreshTokenInResponse() throws Exception {
		mockValidResponse();

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
	}

	@Test
	public void allRequiredParametersAreUsed() throws Exception {
		executeRequest();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS), eq(
								USERNAME),
						eq(PASSWORD), any(), any(), eq(false));
	}

	@Test
	public void subdomainIsUsed() throws Exception {
		String newSubdomain = "staging";
		createValidRequest().subdomain(newSubdomain).execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), eq(newSubdomain), any(), anyBoolean());
	}

	@Test
	public void disableCacheIsUsed() throws Exception {
		createValidRequest().disableCache(true).execute();
		verifyThatDisableCacheIs(true);

		createValidRequest().disableCache(false).execute();
		verifyThatDisableCacheIs(false);
	}

	@Test
	public void additionalParametersAreUsed() throws Exception {
		String key = "aKey";
		String value = "aValue";
		Map<String, String> givenParameters = Maps.newHashMap(key, value);
		Map<String, String> equalParameters = Maps.newHashMap(key, value);

		createValidRequest().optionalParameters(givenParameters).execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), any(), eq(equalParameters), anyBoolean());
	}

	private OAuth2TokenResponse executeRequest() throws TokenFlowException {
		return createValidRequest().execute();
	}

	private PasswordTokenFlow createValidRequest() {
		return cut.username(USERNAME).password(PASSWORD);
	}

	private void mockValidResponse() throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(ACCESS_TOKEN, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI, CLIENT_CREDENTIALS, USERNAME,
				PASSWORD,
				null, null, false))
				.thenReturn(validResponse);
	}

	private void mockValidResponse(String accessToken) throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(accessToken, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI, CLIENT_CREDENTIALS, USERNAME,
				PASSWORD, null, null, false))
				.thenReturn(validResponse);
	}

	private void verifyThatDisableCacheIs(boolean disableCache) throws OAuth2ServiceException {
		verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), any(), any(), eq(disableCache));
	}
}
