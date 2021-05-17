/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_ENDPOINT_URI = URI.create("https://tokenKeys.io/token_keys");
	private final String jsonWebKeysAsString;

	private DefaultOAuth2TokenKeyService cut;
	private CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() {
		httpClient = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOAuth2TokenKeyService(httpClient);
	}

	@Test
	public void httpClient_isNull_throwsException() {
		assertThatThrownBy(() -> new DefaultOAuth2TokenKeyService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_responseNotOk_throwsException() throws IOException {
		String errorDescription = "Something wen't wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any())).thenReturn(response);

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_ENDPOINT_URI))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription);
	}

	@Test
	public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveTokenKeys(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClient.execute(any())).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_ENDPOINT_URI))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage);
	}

	@Test
	public void retrieveTokenKeys_executesHttpGetRequestWithCorrectURI() throws IOException {
		mockResponse();

		cut.retrieveTokenKeys(TOKEN_ENDPOINT_URI);

		Mockito.verify(httpClient, times(1)).execute(argThat(isHttpGetAndContainsCorrectURI()));

	}

	private CloseableHttpResponse mockResponse() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(jsonWebKeysAsString);
		when(httpClient.execute(any())).thenReturn(response);
		return response;
	}

	private ArgumentMatcher<HttpUriRequest> isHttpGetAndContainsCorrectURI() {
		return (httpGet) -> {
			boolean hasCorrectURI = httpGet.getURI().equals(TOKEN_ENDPOINT_URI);
			boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
			return hasCorrectURI && correctMethod;
		};
	}
}