package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ACCESS_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.EXPIRES_IN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaOAuth2TokenServiceClientCredentialsTest {

	OAuth2TokenService cut;
	ClientCredentials clientCredentials;
	URI tokenEndpoint;
	Map<String, String> responseMap;

	@Mock
	RestOperations mockRestOperations;

	@Before
	public void setup() {
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
		clientCredentials = new ClientCredentials("clientid", "mysecretpassword");
		tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");

		responseMap = new HashMap<>();
		responseMap.putIfAbsent(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		responseMap.putIfAbsent(EXPIRES_IN, "43199");
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaClientCredentialsGrant(null, clientCredentials, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpointUri");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint, null, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientCredentials");
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusUnauthorized() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
		cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint, clientCredentials,
				null, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusNotOk() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
		cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint, clientCredentials,
				null, null);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setClientCredentials(clientCredentials);
		tokenHttpEntityMatcher.setGrantType(GRANT_TYPE_CLIENT_CREDENTIALS);

		Mockito.when(mockRestOperations
				.postForEntity(
						eq(tokenEndpoint),
						argThat(tokenHttpEntityMatcher),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint,
				clientCredentials,
				null, null);
		assertThat(accessToken.getAccessToken(), is(responseMap.get(ACCESS_TOKEN)));
		assertNotNull(accessToken.getExpiredAtDate());
	}

	@Test
	public void retrieveToken_withOptionalParamaters() throws OAuth2ServiceException {
		Map<String, String> additionalParameters = new HashMap<>();
		additionalParameters.put("add-param-1", "value1");
		additionalParameters.put("add-param-2", "value2");

		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setClientCredentials(clientCredentials);
		tokenHttpEntityMatcher.setGrantType(GRANT_TYPE_CLIENT_CREDENTIALS);
		tokenHttpEntityMatcher.addParameters(additionalParameters);

		Mockito.when(mockRestOperations.postForEntity(
				eq(tokenEndpoint),
				argThat(tokenHttpEntityMatcher),
				eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint,
				clientCredentials, null,
				additionalParameters);
		assertThat(accessToken.getAccessToken(), is(responseMap.get(ACCESS_TOKEN)));
	}

	@Test
	public void retrieveToken_requiredParametersCanNotBeOverwritten() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setClientCredentials(clientCredentials);
		tokenHttpEntityMatcher.setGrantType(GRANT_TYPE_CLIENT_CREDENTIALS);

		Mockito.when(mockRestOperations.postForEntity(
				eq(tokenEndpoint),
				argThat(tokenHttpEntityMatcher),
				eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> overwrittenGrantType = new HashMap<>();
		overwrittenGrantType.put(GRANT_TYPE, "overwrite-obligatory-param");

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint,
				clientCredentials, null,
				overwrittenGrantType);
		assertThat(accessToken.getAccessToken(), is(responseMap.get(ACCESS_TOKEN)));
	}

}