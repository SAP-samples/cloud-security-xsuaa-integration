/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class XsuaaOAuth2TokenServicePasswordTest {

	private OAuth2TokenService cut;

	private final String clientSecret = "test321";
	private final String clientId = "theClientId";
	private final String password = "test123";
	private final String username = "bob";
	private final String subdomain = "subdomain";
	private final ClientIdentity clientIdentity = new ClientCredentials(clientId, clientSecret);
	private final URI tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");
	private Map<String, String> optionalParameters;
	private Map<String, String> response;

	@Mock
	private RestOperations mockRestOperations;

	@BeforeEach
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

	@Test
	public void retrieveToken_httpStatusUnauthorized_throwsException() {
		assertThrows(OAuth2ServiceException.class, () -> {
			throwExceptionOnPost(HttpStatus.UNAUTHORIZED);

			cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
					username, password, null, null, false);
		});
	}

	@Test
	public void retrieveToken_httpStatusNotOk_throwsException() {
		assertThrows(OAuth2ServiceException.class, () -> {
			throwExceptionOnPost(HttpStatus.BAD_REQUEST);

			cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
					username, password, null, null, false);
		});
	}

	@Test
	public void retrieveToken_requiredParametersMissing_throwsException() {
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(null, clientIdentity,
				username, password, subdomain, optionalParameters, false)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, null,
				username, password, subdomain, optionalParameters, false)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				null, password, subdomain, optionalParameters, false)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, null, subdomain, optionalParameters, false)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveToken_callsTokenEndpoint() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null, false);

		Mockito.verify(mockRestOperations, times(1))
				.postForEntity(eq(tokenEndpoint), any(), any());
	}

	@Test
	public void retrieveToken_setsCorrectGrantType() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null, false);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		String actualGrantType = valueOfParameter(GRANT_TYPE, requestEntityCaptor);
		assertThat(actualGrantType).isEqualTo(GRANT_TYPE_PASSWORD);
	}

	@Test
	public void retrieveToken_setsUsername() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null, false);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(USERNAME, requestEntityCaptor)).isEqualTo(username);
	}

	@Test
	public void retrieveToken_setsPassword() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null, false);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(PASSWORD, requestEntityCaptor)).isEqualTo(password);
	}

	@Test
	public void retrieveToken_setsClientCredentials() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null, false);

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
				username, password, null, optionalParameters, false);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();
		assertThat(valueOfParameter(tokenFormatParameterKey, requestEntityCaptor)).isEqualTo(tokenFormat);
		assertThat(valueOfParameter(loginHintParameterKey, requestEntityCaptor)).isEqualTo(loginHint);
	}

	@Test
	public void retrieveToken_setsCorrectHeaders() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, optionalParameters, false);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();
		HttpHeaders headers = requestEntityCaptor.getValue().getHeaders();

		assertThat(headers.getAccept()).containsExactly(MediaType.APPLICATION_JSON);
		assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		OAuth2TokenResponse actualResponse = cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity,
				username, password, null, null, false);

		assertThat(actualResponse.getAccessToken()).isEqualTo(response.get(ACCESS_TOKEN));
		assertThat(actualResponse.getTokenType()).isEqualTo(response.get(TOKEN_TYPE));
		assertThat(actualResponse.getExpiredAt()).isNotNull();
	}

	@Test
	public void retrieveToken_testCache() throws IOException {
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity, username, password, null, emptyMap(),
				false);
		cut.retrieveAccessTokenViaPasswordGrant(tokenEndpoint, clientIdentity, username, password, null, emptyMap(),
				false);

		verify(mockRestOperations, times(1)).postForEntity(any(), any(), any());
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
