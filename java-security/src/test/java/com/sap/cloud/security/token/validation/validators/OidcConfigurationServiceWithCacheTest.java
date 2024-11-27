/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class OidcConfigurationServiceWithCacheTest {
	OidcConfigurationServiceWithCache cut;
	OidcConfigurationService oidcConfigServiceMock;
	OAuth2ServiceEndpointsProvider oidcEndpointsProviderMock;
	URI DISCOVERY_URI = URI.create("https://myauth.com/.well-known/oidc-config");

	@BeforeEach
	public void setup() throws IOException {
		oidcEndpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigServiceMock.retrieveEndpoints(any()))
				.thenReturn(oidcEndpointsProviderMock);

		cut = OidcConfigurationServiceWithCache.getInstance().withOidcConfigurationService(oidcConfigServiceMock);
	}

	@Test
	public void getFreshInstance() {
		Assertions.assertThat(cut).isNotSameAs(OidcConfigurationServiceWithCache.getInstance());
	}

	@Test
	public void changeCacheConfiguration() {
		cut = cut.withCacheSize(1001).withCacheTime(600);

		assertThatThrownBy(() -> {
			cut = cut.withCacheSize(1000).withCacheTime(600);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("size");

		assertThatThrownBy(() -> {
			cut = cut.withCacheSize(1001).withCacheTime(599);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("validity");

		assertThatThrownBy(() -> {
			cut = cut.withCacheSize(1001).withCacheTime(901);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("validity");
	}

	@Test
	public void retrieveEndpoints() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		OAuth2ServiceEndpointsProvider endpointsProvider = cut.getOrRetrieveEndpoints(DISCOVERY_URI);
		Assertions.assertThat(endpointsProvider).isSameAs(oidcEndpointsProviderMock);

		Mockito.verify(oidcConfigServiceMock, times(1))
				.retrieveEndpoints(DISCOVERY_URI);
	}

	@Test
	public void getCachedEndpoints() throws OAuth2ServiceException {
		OAuth2ServiceEndpointsProvider endpointsProvider = cut.getOrRetrieveEndpoints(DISCOVERY_URI);

		OAuth2ServiceEndpointsProvider cachedEndpointsProvider = cut.getOrRetrieveEndpoints(DISCOVERY_URI);
		Assertions.assertThat(cachedEndpointsProvider).isNotNull();
		Assertions.assertThat(cachedEndpointsProvider).isSameAs(endpointsProvider);

		Mockito.verify(oidcConfigServiceMock, times(1))
				.retrieveEndpoints(DISCOVERY_URI);
	}

	@Test
	public void retrieveNoEndpoints_returnsNull()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.withOidcConfigurationService(Mockito.mock(OidcConfigurationService.class));
		OAuth2ServiceEndpointsProvider endpointsProvider = cut.getOrRetrieveEndpoints(DISCOVERY_URI);
		Assertions.assertThat(endpointsProvider).isNull();
	}

	@Test
	public void requestFails_throwsException() throws OAuth2ServiceException {
		when(oidcConfigServiceMock.retrieveEndpoints(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));

		assertThatThrownBy(() ->
			cut.getOrRetrieveEndpoints(DISCOVERY_URI)).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Currently unavailable");
	}

	@Test
	public void retrieveEndpoints_afterCacheWasCleared()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getOrRetrieveEndpoints(DISCOVERY_URI);

		cut.clearCache();

		OAuth2ServiceEndpointsProvider cachedEndpointsProvider = cut.getOrRetrieveEndpoints(DISCOVERY_URI);
		Assertions.assertThat(cachedEndpointsProvider).isNotNull();

		Mockito.verify(oidcConfigServiceMock, times(2))
				.retrieveEndpoints(DISCOVERY_URI);
	}

	@Test
	public void retrieveEndpointsForAnotherIssuer()
			throws OAuth2ServiceException {
		cut.getOrRetrieveEndpoints(DISCOVERY_URI);
		cut.getOrRetrieveEndpoints(URI.create("http://another/url"));

		Mockito.verify(oidcConfigServiceMock, times(2))
				.retrieveEndpoints(any());
	}

}
