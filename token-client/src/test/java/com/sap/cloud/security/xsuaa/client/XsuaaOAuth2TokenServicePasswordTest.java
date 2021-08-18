/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaOAuth2TokenServicePasswordTest {

	private OAuth2TokenService cut;

	private String clientSecret = "test321";
	private String clientId = "theClientId";
	private String password = "test123";
	private String username = "bob";
	private String subdomain = "subdomain";
	private ClientIdentity clientIdentity = new ClientCredentials(clientId, clientSecret);
	private URI tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");
	private Map<String, String> optionalParameters;
	private Map<String, String> response;

	@Mock
	private RestOperations mockRestOperations;

	@Before
	public void setup() {
		response = new HashMap();
		response.putIfAbsent(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		response.putIfAbsent(EXPIRES_IN, "43199");
		response.putIfAbsent(TOKEN_TYPE, "bearer");
		when(mockRestOperations.postForEntity(any(), any(), any()))
				.thenReturn(ResponseEntity.status(200).body(response));
		optionalParameters = new HashMap<>();
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_httpStatusUnauthorized_throwsException() throws OAuth2ServiceException {
		throwExceptionOnPost(HttpStatus.UNAUTHORIZED);

		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_httpStatusNotOk_throwsException() throws OAuth2ServiceException {
		throwExceptionOnPost(HttpStatus.BAD_REQUEST);

		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);
	}

	@Test
	public void retrieveToken_requiredParametersMissing_throwsException() {
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(null, clientIdentity,
				username, password, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, null,
				username, password, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				null, password, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, null, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveToken_callsTokenEndpoint() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);

		Mockito.verify(mockRestOperations, times(1))
				.postForEntity(eq(tokenEndpoint), any(), any());
	}

	@Test
	public void retrieveToken_setsCorrectGrantType() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		String actualGrantType = valueOfParameter(GRANT_TYPE, requestEntityCaptor);
		assertThat(actualGrantType).isEqualTo(GRANT_TYPE_PASSWORD);
	}

	@Test
	public void retrieveToken_setsUsername() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(USERNAME, requestEntityCaptor)).isEqualTo(username);
	}

	@Test
	public void retrieveToken_setsPassword() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(PASSWORD, requestEntityCaptor)).isEqualTo(password);
	}

	@Test
	public void retrieveToken_setsClientCredentials() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(CLIENT_ID, requestEntityCaptor)).isEqualTo(clientIdentity.getId());
		assertThat(valueOfParameter(CLIENT_SECRET, requestEntityCaptor)).isEqualTo(clientIdentity.getSecret());
	}

	@Test
	public void retrieveToken_setsOptionalParameters() throws OAuth2ServiceException {
		String tokenFormatParameterKey = "token_format";
		String tokenFormat = "opaque";
		String loginHintParameterKey = "login_hint";
		String loginHint = "origin";

		optionalParameters.put(tokenFormatParameterKey, tokenFormat);
		optionalParameters.put(loginHintParameterKey, loginHint);

		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, optionalParameters);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();
		assertThat(valueOfParameter(tokenFormatParameterKey, requestEntityCaptor)).isEqualTo(tokenFormat);
		assertThat(valueOfParameter(loginHintParameterKey, requestEntityCaptor)).isEqualTo(loginHint);
	}

	@Test
	public void retrieveToken_setsCorrectHeaders() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, optionalParameters);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();
		HttpHeaders headers = requestEntityCaptor.getValue().getHeaders();

		assertThat(headers.getAccept()).containsExactly(MediaType.APPLICATION_JSON);
		assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		OAuth2TokenResponse actualResponse = cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null);

		assertThat(actualResponse.getAccessToken()).isEqualTo(response.get(ACCESS_TOKEN));
		assertThat(actualResponse.getTokenType()).isEqualTo(response.get(TOKEN_TYPE));
		assertThat(actualResponse.getExpiredAtDate()).isNotNull();
	}

	private ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> captureRequestEntity() {
		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = ArgumentCaptor
				.forClass(HttpEntity.class);
		Mockito.verify(mockRestOperations, times(1))
				.postForEntity(
						eq(tokenEndpoint),
						requestEntityCaptor.capture(),
						eq(Map.class));
		return requestEntityCaptor;
	}

	private String valueOfParameter(
			String parameterKey, ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor) {
		MultiValueMap<String, String> body = requestEntityCaptor.getValue().getBody();
		return body.getFirst(parameterKey);
	}

	private void throwExceptionOnPost(HttpStatus unauthorized) {
		when(mockRestOperations.postForEntity(any(), any(), any()))
				.thenThrow(new HttpClientErrorException(unauthorized));
	}

}