/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.github.benmanes.caffeine.cache.Ticker;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import org.assertj.core.util.Maps;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;

import static java.time.ZoneOffset.UTC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AbstractOAuth2TokenServiceTest {

	public static final URI TOKEN_ENDPOINT_URI = URI.create("http://test.token.endpoint/oauth/token");
	public static final String SUBDOMAIN = "subdomain";
	public static final String ZONE_ID = "zone";
	private static final Instant NOW = LocalDateTime.of(2020, 1, 1, 0, 0, 0, 0).toInstant(UTC);
	public static final TokenCacheConfiguration TEST_CACHE_CONFIGURATION = TokenCacheConfiguration
			.defaultConfiguration();

	private TestOAuth2TokenService cut;

	@BeforeEach
	public void setUp() {
		cut = new TestOAuth2TokenService(TEST_CACHE_CONFIGURATION);
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_activeCache_responseNotNull() throws OAuth2ServiceException {
		OAuth2TokenResponse oAuth2TokenResponse = retrieveAccessTokenViaClientCredentials();
		assertThat(oAuth2TokenResponse).isNotNull();
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_noCache_responseNotNull() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(TokenCacheConfiguration.cacheDisabled());
		OAuth2TokenResponse oAuth2TokenResponse = retrieveAccessTokenViaClientCredentials();
		assertThat(oAuth2TokenResponse).isNotNull();
	}

	@Test
	public void retrieveAccessTokenViaRefreshToken_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaRefreshToken("refreshToken");
		retrieveAccessTokenViaRefreshToken("another refreshToken");
		retrieveAccessTokenViaRefreshToken("refreshToken");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaPasswordGrant_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaPasswordGrant("user1");
		retrieveAccessTokenViaPasswordGrant("user2");
		retrieveAccessTokenViaPasswordGrant("user1");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaClientCredentials();
		retrieveAccessTokenViaClientCredentials(new ClientCredentials("other client id", "secret"), false);
		retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_forDifferentZoneIds_TwoRequestCalls()
			throws OAuth2ServiceException {
		cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI, clientIdentity(), "ZONE-ID", SUBDOMAIN,
				null, false);
		cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI, clientIdentity(), "ZONE-ID", SUBDOMAIN,
				null, false);
		cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI, clientIdentity(), "OTHER_ZONE-ID",
				SUBDOMAIN, null, false);

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaJwtBearerTokenGrant_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaJwtBearerTokenGrant("token");
		retrieveAccessTokenViaJwtBearerTokenGrant("differentToken");
		retrieveAccessTokenViaJwtBearerTokenGrant("token");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_differentTokenEndpoint_requestsFreshToken() throws OAuth2ServiceException {
		retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI);
		retrieveAccessTokenViaPasswordGrant(URI.create("http://another.token.endpoint"));

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_differentSubdomain_requestsFreshToken() throws OAuth2ServiceException {
		retrieveAccessTokenViaRefreshToken("token", "subdomain1");
		retrieveAccessTokenViaRefreshToken("token", "subdomain2");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_differentAdditionalParameters_requestsFreshToken() throws OAuth2ServiceException {
		retrieveAccessTokenViaJwtBearerTokenGrant("token", Maps.newHashMap("a", "b"));
		retrieveAccessTokenViaJwtBearerTokenGrant("token", Maps.newHashMap("1", "2"));

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_sameAdditionalParameters_onlyOneRequestCall() throws OAuth2ServiceException {
		Map<String, String> parameters = Maps.newHashMap("a", "b");
		parameters.put("c", "d");
		Map<String, String> sameParametersDifferentOrder = Maps.newHashMap("c", "d");
		sameParametersDifferentOrder.put("a", "b");

		retrieveAccessTokenViaJwtBearerTokenGrant("token", parameters);
		retrieveAccessTokenViaJwtBearerTokenGrant("token", sameParametersDifferentOrder);

		assertThat(cut.tokenRequestCallCount).isOne();
	}

	@Test
	public void requestAccessToken_cacheGloballyDisabled_requestsFreshTokens() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(TokenCacheConfiguration.cacheDisabled());

		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
	}

	@Test
	public void clearCache_requestsFreshToken() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		cut.clearCache();
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
	}

	@Test
	public void requestAccessToken_cachedTokens_areTheSame() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(firstResponse).isSameAs(secondResponse);
		assertThat(cut.tokenRequestCallCount).isEqualTo(1);
	}

	@Test
	public void requestAccessToken_tokensAreInvalidatedAfterTime_requestsFreshToken() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		cut.advanceTime(TEST_CACHE_CONFIGURATION.getCacheDuration());
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
	}

	@Test
	public void requestAccessToken_cacheIsFull_requestsFreshToken() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(cacheConfigurationWithSize(1));
		OAuth2TokenResponse user1Response = retrieveAccessTokenViaPasswordGrant("user1");
		OAuth2TokenResponse user2Response = retrieveAccessTokenViaPasswordGrant("user2");
		OAuth2TokenResponse secondUser1Response = retrieveAccessTokenViaPasswordGrant("user1");

		assertThat(user1Response).isNotSameAs(secondUser1Response).isNotSameAs(user2Response);
		assertThat(cut.tokenRequestCallCount).isEqualTo(3);
	}

	@Test
	public void requestAccessToken_cacheDisabledForRequest_requestsFreshTokens() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials(clientIdentity(), false);
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials(clientIdentity(), true);
		OAuth2TokenResponse lastResponse = retrieveAccessTokenViaClientCredentials(clientIdentity(), false);

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse).isSameAs(lastResponse);
	}

	@Test
	public void requestAccessToken_expiredToken_requestsFreshTokens() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(TEST_CACHE_CONFIGURATION);
		cut.setExpiredAt(NOW.minus(Duration.ofHours(1)));

		retrieveAccessTokenViaClientCredentials();
		retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_expireNotInDelta_cacheUsed() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(cacheConfigurationWithDelta(Duration.ofSeconds(10)));
		cut.setExpiredAt(NOW.plus(Duration.ofSeconds(30)));

		retrieveAccessTokenViaClientCredentials();
		retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(1);
	}

	@Test
	public void requestAccessToken_timeAdvancedAndGotExpired_requestsFreshToken() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(cacheConfigurationWithDelta(Duration.ofSeconds(10)));
		cut.setExpiredAt(NOW.plus(Duration.ofSeconds(30)));

		retrieveAccessTokenViaClientCredentials();
		cut.advanceTime(Duration.ofSeconds(25));
		retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void cacheStatistics_isDisabled_statisticsObjectIsNull() {
		TokenCacheConfiguration tokenCacheConfiguration = cacheConfigurationWithCacheStatistics(false);
		cut = new TestOAuth2TokenService(tokenCacheConfiguration);

		assertThat(cut.getCacheStatistics()).isNull();
	}

	@Test
	public void cacheStatistics_isEnabled_returnsStatisticsObject() {
		TokenCacheConfiguration tokenCacheConfiguration = cacheConfigurationWithCacheStatistics(true);
		cut = new TestOAuth2TokenService(tokenCacheConfiguration);

		assertThat(cut.getCacheStatistics()).isInstanceOf(CacheStats.class);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(String token) throws OAuth2ServiceException {
		return retrieveAccessTokenViaJwtBearerTokenGrant(token, null);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(String token,
			Map<String, String> optionalParameters) throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaJwtBearerTokenGrant(TOKEN_ENDPOINT_URI, clientIdentity(), token, null,
				optionalParameters, false);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaClientCredentials() throws OAuth2ServiceException {
		return retrieveAccessTokenViaClientCredentials(clientIdentity(), false);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaClientCredentials(ClientIdentity clientIdentity,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI, clientIdentity, ZONE_ID,
				SUBDOMAIN,
				null, disableCacheForRequest);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(String username) throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI, clientIdentity(), username, "password",
				SUBDOMAIN, null, false);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri)
			throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaPasswordGrant(tokenEndpointUri, clientIdentity(), "username", "password",
				SUBDOMAIN, null, false);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(String refreshToken) throws OAuth2ServiceException {
		return retrieveAccessTokenViaRefreshToken(refreshToken, SUBDOMAIN);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(String refreshToken, String subdomain)
			throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaRefreshToken(TOKEN_ENDPOINT_URI, clientIdentity(), refreshToken, subdomain,
				false);
	}

	private ClientIdentity clientIdentity() {
		return new ClientCredentials("clientId", "clientSecret");
	}

	private TokenCacheConfiguration cacheConfigurationWithDelta(Duration delta) {
		return TokenCacheConfiguration.getInstance(TEST_CACHE_CONFIGURATION.getCacheDuration(),
				TEST_CACHE_CONFIGURATION.getCacheSize(), delta);
	}

	private TokenCacheConfiguration cacheConfigurationWithSize(int size) {
		return TokenCacheConfiguration.getInstance(TEST_CACHE_CONFIGURATION.getCacheDuration(), size,
				TEST_CACHE_CONFIGURATION.getTokenExpirationDelta());
	}

	private TokenCacheConfiguration cacheConfigurationWithCacheStatistics(boolean enableCacheStatistics) {
		return TokenCacheConfiguration.getInstance(TEST_CACHE_CONFIGURATION.getCacheDuration(),
				TEST_CACHE_CONFIGURATION.getCacheSize(), TEST_CACHE_CONFIGURATION.getTokenExpirationDelta(),
				enableCacheStatistics);
	}

	private static class TestOAuth2TokenService extends AbstractOAuth2TokenService {

		private final static TestCacheTicker testCacheTicker = new TestCacheTicker();
		private int tokenRequestCallCount = 0;
		private Instant expiredAt = NOW.plus(Duration.ofDays(1));
		private Clock clock = Clock.fixed(NOW, UTC);

		public TestOAuth2TokenService(TokenCacheConfiguration tokenCacheConfiguration) {
			super(tokenCacheConfiguration, testCacheTicker, true);
			testCacheTicker.reset();
		}

		public void setExpiredAt(Instant expiredAt) {
			this.expiredAt = expiredAt;
		}

		public void advanceTime(Duration duration) {
			clock = Clock.offset(clock, duration);
			testCacheTicker.advance(duration);
		}

		@Override
		protected Clock getClock() {
			return clock;
		}

		@Override
		protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
				Map<String, String> parameters) {
			tokenRequestCallCount++;
			OAuth2TokenResponse responseMock = mock(OAuth2TokenResponse.class);
			when(responseMock.getAccessToken()).thenReturn("token");
			when(responseMock.getExpiredAt()).thenReturn(expiredAt);
			return responseMock;
		}
	}

	private static class TestCacheTicker implements Ticker {
		long elapsed = 0;

		@Override
		public long read() {
			return elapsed;
		}

		public void advance(Duration duration) {
			this.elapsed = elapsed + duration.toNanos();
		}

		public void reset() {
			elapsed = 0;
		}
	}
}
