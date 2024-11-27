/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class SpringOidcConfigurationServiceTest {
	public static final URI CONFIG_ENDPOINT_URI = URI.create("https://sub.myauth.com" + DISCOVERY_ENDPOINT_DEFAULT);

	private RestOperations restOperationsMock;
	private SpringOidcConfigurationService cut;

	private final String jsonOidcConfiguration;

	public SpringOidcConfigurationServiceTest() throws IOException {
		jsonOidcConfiguration = IOUtils.resourceToString("/oidcConfiguration.json", StandardCharsets.UTF_8);
	}

	@BeforeEach
	public void setUp() throws Exception {
		restOperationsMock = mock(RestOperations.class);
		cut = new SpringOidcConfigurationService(restOperationsMock);
	}

	@Test
	public void restOperations_isNull_throwsException() {
		assertThatThrownBy(() -> new SpringOidcConfigurationService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_parameterIsNull_throwsException() {
		assertThatThrownBy(() -> retrieveEndpoints(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_badRequest_throwsException() {
		String errorDescription = "Something went wrong";
		mockResponse(errorDescription, HttpStatus.BAD_REQUEST);
		assertThatThrownBy(this::retrieveEndpoints)
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription);
	}

	@Test
	public void retrieveEndpoints_executesHttpGetRequestWithCorrectURI() throws OAuth2ServiceException {
		mockResponse();

		retrieveEndpoints();

		Mockito.verify(restOperationsMock, times(1))
				.exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
	}

	@Test
	public void retrieveEndpoints_containsBothKeys() throws OAuth2ServiceException {
		mockResponse();

		OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

		assertThat(result.getTokenEndpoint()).hasToString("http://localhost/oauth/token");
		assertThat(result.getJwksUri()).hasToString("http://localhost/token_keys");
		assertThat(result.getAuthorizeEndpoint()).hasToString("http://localhost/oauth/authorize");
	}

	private void mockResponse() {
		mockResponse(jsonOidcConfiguration, HttpStatus.OK);
	}

	private void mockResponse(String responseAsString, HttpStatus httpStatus) {
		ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(responseAsString, httpStatus);
		when(restOperationsMock.exchange(any(URI.class), eq(HttpMethod.GET), any(), eq(String.class)))
				.thenReturn(stringResponseEntity);
	}

	private OAuth2ServiceEndpointsProvider retrieveEndpoints() throws OAuth2ServiceException {
		return retrieveEndpoints(CONFIG_ENDPOINT_URI);
	}

	private OAuth2ServiceEndpointsProvider retrieveEndpoints(URI endpointsEndpointUri) throws OAuth2ServiceException {
		return cut.retrieveEndpoints(endpointsEndpointUri);
	}
}
