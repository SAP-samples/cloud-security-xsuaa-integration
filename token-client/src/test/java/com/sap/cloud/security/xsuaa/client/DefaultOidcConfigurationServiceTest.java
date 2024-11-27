/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOidcConfigurationServiceTest {
	public static final URI CONFIG_ENDPOINT_URI = URI.create("https://sub.myauth.com" + DISCOVERY_ENDPOINT_DEFAULT);

	private final String jsonOidcConfiguration;

	private CloseableHttpClient httpClientMock;
	private DefaultOidcConfigurationService cut;

	public DefaultOidcConfigurationServiceTest() throws IOException {
		jsonOidcConfiguration = IOUtils.resourceToString("/oidcConfiguration.json", StandardCharsets.UTF_8);
	}

	@BeforeEach
	public void setUp() {
		httpClientMock = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOidcConfigurationService(httpClientMock);
	}

	@Test
	public void httpClient_isNull_throwsException() {
		assertThatThrownBy(() -> new DefaultOidcConfigurationService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_parameterIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveEndpoints(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_badRequest_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClientMock.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(this::retrieveEndpoints)
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription);
	}

	@Test
	public void retrieveEndpoints_executesHttpGetRequestWithCorrectURI() throws IOException {
		mockResponse();

		retrieveEndpoints();

		Mockito.verify(httpClientMock, times(1)).execute(argThat(isHttpGetAndContainsCorrectURI()),
				any(ResponseHandler.class));
	}

	@Test
	public void retrieveEndpoints_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClientMock.execute(any(), any(ResponseHandler.class))).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(this::retrieveEndpoints)
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage)
				.extracting(OAuth2ServiceException.class::cast)
				.extracting(OAuth2ServiceException::getHttpStatusCode).isEqualTo(0);
	}

	@Test
	public void retrieveIssuerEndpoints_executesHttpGetRequestWithCorrectURI() {
		URI discoveryEndpoint1 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com");
		URI discoveryEndpoint2 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com/");
		URI discoveryEndpoint3 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com/path");
		URI discoveryEndpoint4 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com//path");
		URI discoveryEndpoint5 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("sub.myauth.com/path");

		assertThat(discoveryEndpoint1).hasToString("https://sub.myauth.com/.well-known/openid-configuration");
		assertThat(discoveryEndpoint2).hasToString("https://sub.myauth.com/.well-known/openid-configuration");
		assertThat(discoveryEndpoint3).hasToString("https://sub.myauth.com/path/.well-known/openid-configuration");
		assertThat(discoveryEndpoint4).hasToString("https://sub.myauth.com/path/.well-known/openid-configuration");
		assertThat(discoveryEndpoint5).hasToString("https://sub.myauth.com/path/.well-known/openid-configuration");
	}

	@Test
	public void retrieveEndpoints_containsBothKeys() throws IOException {
		mockResponse();

		OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

		assertThat(result.getTokenEndpoint()).hasToString("http://localhost/oauth/token");
		assertThat(result.getJwksUri()).hasToString("http://localhost/token_keys");
		assertThat(result.getAuthorizeEndpoint()).hasToString("http://localhost/oauth/authorize");
	}

	private void mockResponse() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(jsonOidcConfiguration);
		when(httpClientMock.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});
	}

	private OAuth2ServiceEndpointsProvider retrieveEndpoints() throws OAuth2ServiceException {
		return cut.retrieveEndpoints(CONFIG_ENDPOINT_URI);
	}

	private ArgumentMatcher<HttpUriRequest> isHttpGetAndContainsCorrectURI() {
		return (httpGet) -> {
			boolean hasCorrectURI;
			hasCorrectURI = httpGet.getURI().equals(CONFIG_ENDPOINT_URI);
			boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
			return hasCorrectURI && correctMethod;
		};
	}
}
