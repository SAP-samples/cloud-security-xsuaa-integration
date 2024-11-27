/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class JwtBearerTokenFlowTest {

	private OAuth2TokenService tokenService;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private JwtBearerTokenFlow cut;

	@BeforeEach
	public void setUp() {
		tokenService = mock(OAuth2TokenService.class);
		endpointsProvider = mock(OAuth2ServiceEndpointsProvider.class);

		when(endpointsProvider.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT_URI);

		cut = new JwtBearerTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS).token(ACCESS_TOKEN);
	}

	@Test
	public void tokenServiceIsNull_throwsException() {
		assertThatThrownBy(() -> new JwtBearerTokenFlow(null, endpointsProvider, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2TokenService");
	}

	@Test
	public void endpointsProviderIsNull_throwsException() {
		assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, null, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void clientCredentialsAreNull_throwsException() {
		assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, endpointsProvider, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ClientIdentity");
	}

	@Test
	public void execute_bearerTokenIsMissing_throwsException() {
		assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("A bearer token must be set before executing the flow");

		assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS)
				.token((String) null).execute())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Bearer token must not be null");

		assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS)
				.token((Token) null).execute())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Token must");
	}

	@Test
	public void execute_returnsCorrectAccessTokenInResponse() throws Exception {
		mockValidResponse();

		OAuth2TokenResponse actualResponse = cut.execute();

		assertThat(actualResponse.getAccessToken()).isEqualTo(JWT_BEARER_TOKEN);
	}

	@Test
	public void execute_ReturnsRefreshTokenInResponse() throws Exception {
		mockValidResponse();

		OAuth2TokenResponse actualResponse = cut.execute();

		assertThat(actualResponse.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
	}

	@Test
	public void allRequiredParametersAreUsed() throws Exception {
		cut.execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS),
						eq(ACCESS_TOKEN), any(), any(), eq(false));
	}

	@Test
	public void subdomainIsUsed() throws Exception {
		String newSubdomain = "staging";
		cut.subdomain(newSubdomain).execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(),
						eq(newSubdomain), any(), anyBoolean());
	}

	@Test
	public void disableCacheIsUsed() throws Exception {
		cut.disableCache(true).execute();
		verifyThatDisableCacheIs(true);

		cut.disableCache(false).execute();
		verifyThatDisableCacheIs(false);
	}

	@Test
	public void execute_withOpaqueTokenFormat() throws TokenFlowException, OAuth2ServiceException {
		final String OPAQUE = "opaque";
		final String TOKEN_FORMAT = "token_format";
		ArgumentCaptor<Map<String, String>> optionalParametersCaptor = ArgumentCaptor.forClass(Map.class);

		cut.execute();
		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(),
						optionalParametersCaptor.capture(), anyBoolean());
		assertThat(optionalParametersCaptor.getValue()).doesNotContainEntry(TOKEN_FORMAT, OPAQUE);

		cut.setOpaqueTokenFormat(true).execute();
		verify(tokenService, times(2))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(),
						optionalParametersCaptor.capture(), anyBoolean());
		assertThat(optionalParametersCaptor.getValue()).containsEntry(TOKEN_FORMAT, OPAQUE);

		cut.setOpaqueTokenFormat(false).execute();
		verify(tokenService, times(3))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(),
						optionalParametersCaptor.capture(), anyBoolean());
		assertThat(optionalParametersCaptor.getValue()).doesNotContainEntry(TOKEN_FORMAT, OPAQUE);
	}

	@Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException, OAuth2ServiceException {
		Map<String, String> additionalAuthorities = new HashMap<>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");
		Map<String, String> additionalAuthoritiesParam = new HashMap<>();
		additionalAuthoritiesParam.put("authorities", "{\"az_attr\":{\"DummyAttribute\":\"DummyAttributeValue\"}}");

		cut.attributes(additionalAuthorities).execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS),
						eq(ACCESS_TOKEN),
						isNull(), eq(additionalAuthoritiesParam), anyBoolean());
	}

	@Test
	public void execute_withScopes() throws TokenFlowException, OAuth2ServiceException {
		ArgumentCaptor<Map<String, String>> optionalParametersCaptor = ArgumentCaptor.forClass(Map.class);
		mockValidResponse();

		OAuth2TokenResponse response = cut.scopes("scope1", "scope2").execute();

		assertThat(response.getAccessToken()).isSameAs(JWT_BEARER_TOKEN);
		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(),
						optionalParametersCaptor.capture(), anyBoolean());

		Map<String, String> optionalParameters = optionalParametersCaptor.getValue();
		assertThat(optionalParameters).containsEntry("scope", "scope1 scope2");
	}

	@Test
	public void execute_withScopesSetToNull_throwsException() {
		assertThatThrownBy(() -> cut.scopes(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void execute_withZoneId() throws OAuth2ServiceException, TokenFlowException {
		String zoneId = "zone";
		mockResponseWithZoneId(zoneId);

		cut.zoneId(zoneId).execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), eq(ACCESS_TOKEN), anyMap(), eq(false),
						eq(zoneId));
	}

	@Test
	public void execute_withZoneId_fromToken() throws TokenFlowException, OAuth2ServiceException {
		String zoneId = "zone-x";
		Token mockedToken = mock(Token.class);
		when(mockedToken.getTokenValue()).thenReturn(ACCESS_TOKEN);
		when(mockedToken.getZoneId()).thenReturn(zoneId);
		mockResponseWithZoneId(zoneId);

		cut.token(mockedToken).execute();

		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(
						eq(TOKEN_ENDPOINT_URI),
						eq(CLIENT_CREDENTIALS),
						eq(ACCESS_TOKEN),
						anyMap(), anyBoolean(), eq(zoneId));
	}

	private void mockValidResponse() throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(JWT_BEARER_TOKEN, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS),
				eq(ACCESS_TOKEN), any(), any(), eq(false)))
				.thenReturn(validResponse);
	}

	private void mockResponseWithZoneId(String zoneId) throws OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = new OAuth2TokenResponse(ACCESS_TOKEN,
				EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
				eq(TOKEN_ENDPOINT_URI),
				eq(CLIENT_CREDENTIALS),
				eq(ACCESS_TOKEN),
				anyMap(),
				eq(false),
				eq(zoneId))).thenReturn(mockedResponse);
	}

	private void verifyThatDisableCacheIs(boolean disableCache) throws OAuth2ServiceException {
		verify(tokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), any(), eq(disableCache));
	}
}
