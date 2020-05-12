package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ACCESS_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.EXPIRES_IN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.REFRESH_TOKEN;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaOAuth2TokenServiceUserTokenTest {

	OAuth2TokenService cut;
	ClientCredentials clientCredentials;
	URI tokenEndpoint;
	Map<String, String> responseMap;
	private static final String userTokenToBeExchanged = "65a84cd45c554c6993ea26cb8f9cf3a2";

	@Mock
	RestOperations mockRestOperations;

	@Before
	public void setup() {
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
		clientCredentials = new ClientCredentials("clientid", "mysecretpassword");
		tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");

		responseMap = new HashMap<>();
		responseMap.put(REFRESH_TOKEN, "2170b564228448c6aed8b1ddfdb8bf53-r");
		responseMap.put(ACCESS_TOKEN, "4d841646fcc340f59b1b7b43df4b050d"); // opaque access token
		responseMap.put(EXPIRES_IN, "43199");
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaUserTokenGrant(null, clientCredentials, userTokenToBeExchanged, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpointUri");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, null, userTokenToBeExchanged, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientCredentials");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials, null, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusUnauthorized() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
		cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusNotOk() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
		cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null, null);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setGrantType(OAuth2TokenServiceConstants.GRANT_TYPE_USER_TOKEN);
		tokenHttpEntityMatcher.addParameter(OAuth2TokenServiceConstants.PARAMETER_CLIENT_ID, clientCredentials.getId());

		HttpHeaders expectedHeaders = new HttpHeaders();
		expectedHeaders.add(HttpHeaders.ACCEPT, "application/json");
		expectedHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer " + userTokenToBeExchanged);
		HttpEntity expectedRequest = new HttpEntity(expectedHeaders);

		Mockito.when(mockRestOperations
				.postForEntity(
						eq(tokenEndpoint),
						argThat(tokenHttpEntityMatcher),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null, null);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
		assertThat(accessToken.getAccessToken(), is(responseMap.get(ACCESS_TOKEN)));
		assertNotNull(accessToken.getExpiredAtDate());
	}

	@Test
	public void retrieveToken_withOptionalParamaters() throws OAuth2ServiceException {
		Map<String, String> additionalParameters = new HashMap<>();
		additionalParameters.put("add-param-1", "value1");
		additionalParameters.put("add-param-2", "value2");

		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setGrantType(OAuth2TokenServiceConstants.GRANT_TYPE_USER_TOKEN);
		tokenHttpEntityMatcher.addParameter(OAuth2TokenServiceConstants.PARAMETER_CLIENT_ID, clientCredentials.getId());
		tokenHttpEntityMatcher.addParameters(additionalParameters);

		Mockito.when(mockRestOperations.postForEntity(
				eq(tokenEndpoint),
				argThat(tokenHttpEntityMatcher),
				eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null, additionalParameters);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
	}

	@Test
	public void retrieveToken_requiredParametersCanNotBeOverwritten() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setGrantType(OAuth2TokenServiceConstants.GRANT_TYPE_USER_TOKEN);
		tokenHttpEntityMatcher.addParameter(OAuth2TokenServiceConstants.PARAMETER_CLIENT_ID, clientCredentials.getId());

		Mockito.when(
				mockRestOperations.postForEntity(
						eq(tokenEndpoint),
						argThat(tokenHttpEntityMatcher),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> overwrittenGrantType = new HashMap<>();
		overwrittenGrantType.put(OAuth2TokenServiceConstants.GRANT_TYPE, "overwrite-obligatory-param");

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null, overwrittenGrantType);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
	}
}