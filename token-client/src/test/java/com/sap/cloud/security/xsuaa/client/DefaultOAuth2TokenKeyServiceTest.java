/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_OSB_PLAN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://tokenKeys.io/token_keys");
	public static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
	public static final String CLIENT_ID = "client-id";
	public static final String AZP = "azp";
	private static final Map<String, String> PARAMS = Map.of(
			HttpHeaders.X_APP_TID, APP_TID,
			HttpHeaders.X_CLIENT_ID, CLIENT_ID,
			HttpHeaders.X_AZP, AZP);
	private final String jsonWebKeysAsString;

	private DefaultOAuth2TokenKeyService cut;
	private CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@BeforeEach
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
	public void retrieveTokenKeysForZone_responseNotOk_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription)
				.hasMessageContaining("Request headers [")
				.hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
				.hasMessageContaining("x-client_id: client-id")
				.hasMessageContaining("x-azp: azp")
				.hasMessageContaining("'Something went wrong'")
				.hasMessageContaining("Error retrieving token keys")
				.hasMessageContaining("Response Headers [testHeader: testValue]")
				.hasMessageContaining("Http status code 400");
	}

	@Test
	public void retrieveTokenKeys_responseNotOk_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, Collections.emptyMap()))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription)
				.hasMessageContaining("'Something went wrong'")
				.hasMessageContaining("Error retrieving token keys");
	}

	@Test
	public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveTokenKeys(null, PARAMS))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage);
	}

	@Test
	public void retrieveTokenKeys_app2Service_proofToken() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponseWithHeaders(jsonWebKeysAsString,
				new BasicHeader[] { new BasicHeader(X_OSB_PLAN, "\"plan1\"") });

		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		Map<String, String> requestParams = new HashMap<>();
		requestParams.put(HttpHeaders.X_CLIENT_CERT, "cert");
		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, requestParams);
		assertNotNull(SecurityContext.getServicePlans());
		assertThat(SecurityContext.getServicePlans()).containsExactly("plan1");
	}

	@Test
	public void retrieveTokenKeys_app2service_proofToken_multiplePlans() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponseWithHeaders(jsonWebKeysAsString,
				new BasicHeader[] { new BasicHeader(X_OSB_PLAN, "\"plan1\" , \"plan \"two\"\",\"plan3\"") });

		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		Map<String, String> requestParams = new HashMap<>();
		requestParams.put(HttpHeaders.X_CLIENT_CERT, "cert");
		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, requestParams);
		assertThat(SecurityContext.getServicePlans()).containsExactly("plan1", "plan \"two\"", "plan3");
	}

	@Test
	public void retrieveTokenKeys_executesCorrectHttpGetRequest() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(jsonWebKeysAsString);

		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

		Mockito.verify(httpClient, times(1)).execute(argThat(isCorrectHttpGetRequest()),
				any(ResponseHandler.class));
	}

	private ArgumentMatcher<HttpUriRequest> isCorrectHttpGetRequest() {
		return (httpGet) -> {
			boolean hasCorrectURI = httpGet.getURI().equals(TOKEN_KEYS_ENDPOINT_URI);
			boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
			boolean correctTenantHeader = httpGet.getFirstHeader(HttpHeaders.X_APP_TID).getValue().equals(APP_TID);
			boolean correctClientId = httpGet.getFirstHeader(HttpHeaders.X_CLIENT_ID).getValue().equals(CLIENT_ID);
			boolean correctAzp = httpGet.getFirstHeader(HttpHeaders.X_AZP).getValue().equals(AZP);
			return hasCorrectURI && correctMethod && correctTenantHeader && correctClientId && correctAzp;
		};
	}
}
