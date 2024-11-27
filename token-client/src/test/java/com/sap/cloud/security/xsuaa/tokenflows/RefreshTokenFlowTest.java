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
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.TOKEN_ENDPOINT_URI;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.XSUAA_BASE_URI;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RefreshTokenFlowTest {

	@Mock
	private OAuth2TokenService mockTokenService;

	private ClientIdentity clientIdentity;
	private RefreshTokenFlow cut;

	private static final String JWT_ACCESS_TOKEN = "4bfad399ca10490da95c2b5eb4451d53";
	private static final String REFRESH_TOKEN = "99e2cecfa54f4957a782f07168915b69-r";
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	@BeforeEach
	public void setup() {
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(XSUAA_BASE_URI);

		this.clientIdentity = new ClientCredentials("clientId", "clientSecret");
		this.endpointsProvider = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		this.cut = new RefreshTokenFlow(mockTokenService, endpointsProvider, clientIdentity);

	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> new RefreshTokenFlow(null, endpointsProvider, clientIdentity))
				.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> new RefreshTokenFlow(mockTokenService, null, clientIdentity))
				.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> new RefreshTokenFlow(mockTokenService, endpointsProvider, null))
				.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientIdentity");
	}

	@Test
	public void execute_throwsIfMandatoryFieldsNotSet() {
		assertThatThrownBy(() -> cut.execute()).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Refresh token not set");
	}

	@Test
	public void execute() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.refreshToken(REFRESH_TOKEN).execute();

		assertThat(response.getAccessToken(), is(accessToken.getAccessToken()));
		verifyRetrieveAccessTokenCalledWith(REFRESH_TOKEN, false);
	}

	@Test
	public void execute_disableCacheIsUsed() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse accessToken = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.refreshToken(REFRESH_TOKEN).disableCache(true).execute();

		assertThat(response.getAccessToken(), is(accessToken.getAccessToken()));
		verifyRetrieveAccessTokenCalledWith(REFRESH_TOKEN, true);
	}

	@Test
	public void execute_throwsIfServiceRaisesException() throws OAuth2ServiceException {
		when(mockTokenService
				.retrieveAccessTokenViaRefreshToken(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						eq(REFRESH_TOKEN), isNull(), anyBoolean()))
				.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> cut.refreshToken(REFRESH_TOKEN)
				.execute()).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error refreshing token with grant_type 'refresh_token': exception executed REST call");
	}

	private void verifyRetrieveAccessTokenCalledWith(String refreshToken, boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaRefreshToken(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						eq(refreshToken), isNull(), eq(disableCacheForRequest));
	}

	private OAuth2TokenResponse mockRetrieveAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse accessToken = new OAuth2TokenResponse(JWT_ACCESS_TOKEN, 441231, null);
		when(mockTokenService
				.retrieveAccessTokenViaRefreshToken(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						eq(REFRESH_TOKEN), isNull(), anyBoolean()))
				.thenReturn(accessToken);
		return accessToken;
	}

}
