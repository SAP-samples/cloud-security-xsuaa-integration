/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.AUTHORITIES;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.SCOPE;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.TOKEN_ENDPOINT_URI;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.XSUAA_BASE_URI;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ClientCredentialsTokenFlowTest {

	@Mock
	private OAuth2TokenService mockTokenService;

	private ClientIdentity clientIdentity;
	private ClientCredentialsTokenFlow cut;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	private static final String JWT_ACCESS_TOKEN = "4bfad399ca10490da95c2b5eb4451d53";

	@BeforeEach
	public void setup() {
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(XSUAA_BASE_URI);

		this.clientIdentity = new ClientCredentials("clientId", "clientSecret");
		this.endpointsProvider = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		this.cut = new ClientCredentialsTokenFlow(mockTokenService, endpointsProvider, clientIdentity);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new ClientCredentialsTokenFlow(null, endpointsProvider, clientIdentity);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new ClientCredentialsTokenFlow(mockTokenService, null, clientIdentity);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> {
			new ClientCredentialsTokenFlow(mockTokenService, endpointsProvider, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientIdentity");
	}

	@Test
	public void execute_triggersServiceCallWithDefaults() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.execute();

		assertThat(response.getAccessToken()).isSameAs(accessToken.getAccessToken());
		verifyThatDisableCacheAttributeIs(false);
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaClientCredentialsGrant(endpointsProvider.getTokenEndpoint(),
						clientIdentity, null, null, emptyMap(), false);
	}

	@Test
	public void execute_throwsIfServiceRaisesException() throws OAuth2ServiceException {
		when(mockTokenService
				.retrieveAccessTokenViaClientCredentialsGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						isNull(), isNull(), anyMap(), anyBoolean()))
				.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() ->
			cut.execute()).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error requesting technical user token with grant_type 'client_credentials': exception executed REST call");
	}

	@Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException, OAuth2ServiceException {
		ArgumentCaptor<Map<String, String>> optionalParametersCaptor = ArgumentCaptor.forClass(Map.class);

		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();
		Map<String, String> additionalAuthorities = new HashMap<>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");

		OAuth2TokenResponse response = cut.attributes(additionalAuthorities).execute();

		assertThat(response.getAccessToken()).isSameAs(accessToken.getAccessToken());
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaClientCredentialsGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						isNull(), isNull(), optionalParametersCaptor.capture(), anyBoolean());
		Map<String, String> optionalParameters = optionalParametersCaptor.getValue();

		assertThat(optionalParameters).containsKey(AUTHORITIES);
		assertThat(optionalParameters.get(AUTHORITIES)).isNotEmpty();
	}

	@Test
	public void execute_WithScopes() throws OAuth2ServiceException, TokenFlowException {
		ArgumentCaptor<Map<String, String>> optionalParametersCaptor = ArgumentCaptor.forClass(Map.class);

		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.scopes("myFirstScope", "theOtherScope").execute();
		assertThat(response.getAccessToken()).isSameAs(accessToken.getAccessToken());

		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaClientCredentialsGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						isNull(), isNull(), optionalParametersCaptor.capture(), anyBoolean());

		Map<String, String> optionalParameters = optionalParametersCaptor.getValue();
		assertThat(optionalParameters).containsKey(SCOPE);
		assertThat(optionalParameters.get(SCOPE)).isEqualTo("myFirstScope theOtherScope");
	}

	@Test
	public void execute_withScopesSetToNull_throwsException() throws OAuth2ServiceException, TokenFlowException {
		assertThatThrownBy(() -> cut.scopes(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void execute_withCacheDisabled() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.disableCache(true).execute();

		assertThat(response.getAccessToken()).isSameAs(accessToken.getAccessToken());
		verifyThatDisableCacheAttributeIs(true);

		cut.disableCache(false).execute();

		verifyThatDisableCacheAttributeIs(false);

	}

	@Test
	public void execute_withZoneId() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();
		OAuth2TokenResponse response = cut.zoneId("zone").execute();

		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaClientCredentialsGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						eq("zone"), isNull(), anyMap(), anyBoolean());

		assertThat(response.getAccessToken()).isSameAs(accessToken.getAccessToken());

	}

	private void verifyThatDisableCacheAttributeIs(boolean disableCache) throws OAuth2ServiceException {
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaClientCredentialsGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						isNull(), isNull(), anyMap(), eq(disableCache));
	}

	private OAuth2TokenResponse mockRetrieveAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse accessToken = new OAuth2TokenResponse(JWT_ACCESS_TOKEN, 441231, null);

		when(mockTokenService
				.retrieveAccessTokenViaClientCredentialsGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						any(), any(), any(), anyBoolean()))
				.thenReturn(accessToken);
		return accessToken;
	}

}
