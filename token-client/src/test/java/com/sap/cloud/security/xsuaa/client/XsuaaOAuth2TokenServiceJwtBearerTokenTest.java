package com.sap.cloud.security.xsuaa.client;

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
public class XsuaaOAuth2TokenServiceJwtBearerTokenTest {

	private OAuth2TokenService cut;

	private String assertion = "jwtToken";
	private String subdomain = "subdomain";
	private ClientCredentials clientCredentials = new ClientCredentials("theClientId", "test321");
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
		when(mockRestOperations.postForEntity(any(), any(), any()))
				.thenReturn(ResponseEntity.status(200).body(response));
		optionalParameters = new HashMap<>();
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_httpStatusUnauthorized_throwsException() throws OAuth2ServiceException {
		throwExceptionOnPost(HttpStatus.UNAUTHORIZED);

		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_httpStatusNotOk_throwsException() throws OAuth2ServiceException {
		throwExceptionOnPost(HttpStatus.BAD_REQUEST);

		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, null);
	}

	@Test
	public void retrieveToken_requiredParametersMissing_throwsException() {
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaJwtBearerTokenGrant(null, clientCredentials,
				assertion, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, null,
				assertion, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				null, subdomain, optionalParameters)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveToken_callsTokenEndpoint() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, null);

		Mockito.verify(mockRestOperations, times(1))
				.postForEntity(eq(tokenEndpoint), any(), any());
	}

	@Test
	public void retrieveToken_setsCorrectGrantType() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		String actualGrantType = valueOfParameter(GRANT_TYPE, requestEntityCaptor);
		assertThat(actualGrantType).isEqualTo(GRANT_TYPE_JWT_BEARER);
	}

	@Test
	public void retrieveToken_setsAssertion() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(ASSERTION, requestEntityCaptor)).isEqualTo(assertion);
	}

	@Test
	public void retrieveToken_setsClientCredentials() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, null);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();

		assertThat(valueOfParameter(CLIENT_ID, requestEntityCaptor)).isEqualTo(clientCredentials.getId());
		assertThat(valueOfParameter(CLIENT_SECRET, requestEntityCaptor)).isEqualTo(clientCredentials.getSecret());
	}

	@Test
	public void retrieveToken_setsOptionalParameters() throws OAuth2ServiceException {
		String tokenFormatParameterName = "token_format";
		String tokenFormat = "opaque";
		String responseTypeParameterName = "response_type";
		String loginHint = "token";

		optionalParameters.put(tokenFormatParameterName, tokenFormat);
		optionalParameters.put(responseTypeParameterName, loginHint);

		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, optionalParameters);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();
		assertThat(valueOfParameter(tokenFormatParameterName, requestEntityCaptor)).isEqualTo(tokenFormat);
		assertThat(valueOfParameter(responseTypeParameterName, requestEntityCaptor)).isEqualTo(loginHint);
	}

	@Test
	public void retrieveToken_setsCorrectHeaders() throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientCredentials,
				assertion, null, optionalParameters);

		ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> requestEntityCaptor = captureRequestEntity();
		HttpHeaders headers = requestEntityCaptor.getValue().getHeaders();

		assertThat(headers.getAccept()).containsExactly(MediaType.APPLICATION_JSON);
		assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		OAuth2TokenResponse actualResponse = cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint,
				clientCredentials,
				assertion, null, null);

		assertThat(actualResponse.getAccessToken()).isEqualTo(response.get(ACCESS_TOKEN));
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