/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://token.endpoint.io/token_keys");
	public static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
	public static final String CLIENT_ID = "client-id";
	public static final String AZP = "azp";
	private static final Map<String, String> PARAMS = Map.of(
			HttpHeaders.X_APP_TID, APP_TID,
			HttpHeaders.X_CLIENT_ID, CLIENT_ID,
			HttpHeaders.X_AZP, AZP);

	private RestOperations restOperationsMock;
	private SpringOAuth2TokenKeyService cut;

	private final String jsonWebKeysAsString;

	public SpringOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@BeforeEach
	public void setUp() {
		restOperationsMock = mock(RestOperations.class);
		cut = new SpringOAuth2TokenKeyService(restOperationsMock);
	}

	@Test
	public void restOperations_isNull_throwsException() {
		assertThatThrownBy(() -> new SpringOAuth2TokenKeyService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_endpointUriIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveTokenKeys(null, APP_TID))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_usesGivenURI() throws OAuth2ServiceException {
		mockResponse();

		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

		Mockito.verify(restOperationsMock, times(1))
				.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), argThat(httpEntityContainsMandatoryHeaders()),
						eq(String.class));
	}

	@Test
	public void retrieveTokenKeys_badResponse_throwsException() {
		String errorMessage = "useful error message";
		mockResponse(errorMessage, HttpStatus.BAD_REQUEST);

		OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
				() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS));

		assertThat(e.getMessage())
				.contains(TOKEN_KEYS_ENDPOINT_URI.toString())
				.contains(String.valueOf(HttpStatus.BAD_REQUEST.value()))
				.contains("Request headers [Accept: application/json, User-Agent: token-client/")
				.contains("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
				.contains("x-client_id: client-id")
				.contains("x-azp: azp")
				.contains("Response Headers ")
				.contains(errorMessage);
		assertThat(e.getHttpStatusCode()).isEqualTo(400);
		assertThat(e.getHeaders()).hasSize(1);
		assertThat(e.getHeaders()).contains("Content-Type: application/json");
	}

	private void mockResponse() {
		mockResponse(jsonWebKeysAsString, HttpStatus.OK);
	}

	private void mockResponse(String responseAsString, HttpStatus httpStatus) {
		MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
		headers.add("Content-Type", "application/json");
		ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(responseAsString, headers, httpStatus);
		when(restOperationsMock.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
				.thenReturn(stringResponseEntity);
	}

	private ArgumentMatcher<HttpEntity> httpEntityContainsMandatoryHeaders() {
		return (httpGet) -> {
			boolean correctClientId = httpGet.getHeaders().get(HttpHeaders.X_CLIENT_ID).get(0).equals(CLIENT_ID);
			boolean correctAppTid = httpGet.getHeaders().get(HttpHeaders.X_APP_TID).get(0).equals(APP_TID);
			boolean correctAzp = httpGet.getHeaders().get(HttpHeaders.X_AZP).get(0).equals(AZP);
			return correctAppTid && correctClientId && correctAzp;
		};
	}

}
