/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.CLIENT_CREDENTIALS;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.XSUAA_BASE_URI;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class XsuaaTokenFlowsTest {

	private static OAuth2ServiceConfiguration oAuth2ServiceConfiguration;
	private XsuaaTokenFlows cut;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private OAuth2TokenService oAuth2TokenService;
	private RestOperations restOperations;

	@BeforeEach
	public void setup() {
		oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(XSUAA_BASE_URI);
		this.endpointsProvider = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		this.restOperations = Mockito.mock(RestTemplate.class);
		Map responseMap = new HashMap<>();
		responseMap.put(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		responseMap.put(EXPIRES_IN, "43199");
		responseMap.put(TOKEN_TYPE, "bearer");
		Mockito.when(restOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));
		this.oAuth2TokenService = new XsuaaOAuth2TokenService(restOperations);
		cut = new XsuaaTokenFlows(oAuth2TokenService, this.endpointsProvider, CLIENT_CREDENTIALS);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(null, endpointsProvider, CLIENT_CREDENTIALS);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(oAuth2TokenService, null, CLIENT_CREDENTIALS);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientIdentity");

	}

	@Test
	public void startRefreshTokenFlow() {
		RefreshTokenFlow flow = cut.refreshTokenFlow();
		assertNotNull(flow, "RefreshTokenFlow must not be null.");
	}

	@Test
	public void startClientCredentialsFlow() {
		ClientCredentialsTokenFlow flow = cut.clientCredentialsTokenFlow();
		assertNotNull(flow, "ClientCredentialsTokenFlow must not be null.");
	}

	@Test
	public void startPasswordTokenFlow() {
		PasswordTokenFlow flow = cut.passwordTokenFlow();
		assertNotNull(flow, "PasswordTokenFlow must not be null.");
	}

	@Test
	public void versionMismatch() throws TokenFlowException {
		cut = new XsuaaTokenFlows(oAuth2TokenService, this.endpointsProvider,
				new ClientCredentials("sb-spring-netflix-demo!t12291",
						"2Tc2Xz7DNy4KiACwvunulmxF32w="));
		cut.clientCredentialsTokenFlow().execute();
	}

	@Test
	public void disableCaching() throws TokenFlowException {
		OAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restOperations,
				TokenCacheConfiguration.cacheDisabled());
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
				this.endpointsProvider, CLIENT_CREDENTIALS);
		OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow().execute();
		assertNotNull(response);
		assertNotEquals(response, tokenFlows.clientCredentialsTokenFlow().execute());
	}

	@Test
	public void disableCacheOnce() throws TokenFlowException {
		OAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restOperations);
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
				this.endpointsProvider, CLIENT_CREDENTIALS);
		OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow().execute();
		assertNotNull(response);
		assertNotEquals(response, tokenFlows.clientCredentialsTokenFlow()
				.disableCache(true).execute());
	}

	@Test
	public void clearCacheOnDemand() throws TokenFlowException {
		AbstractOAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restOperations);
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
				this.endpointsProvider, CLIENT_CREDENTIALS);
		OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow().execute();
		assertNotNull(response);
		tokenService.clearCache();
		assertNotEquals(response, tokenFlows.clientCredentialsTokenFlow().execute());
	}
}
