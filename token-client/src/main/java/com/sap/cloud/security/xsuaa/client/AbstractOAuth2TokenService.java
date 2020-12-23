package com.sap.cloud.security.xsuaa.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

@java.lang.SuppressWarnings("squid:S1192")
public abstract class AbstractOAuth2TokenService implements OAuth2TokenService, Cacheable {

	private static final Logger LOGGER = LoggerFactory.getLogger(AbstractOAuth2TokenService.class);
	private final Cache<CacheKey, OAuth2TokenResponse> responseCache;
	private final TokenCacheConfiguration tokenCacheConfiguration;

	public AbstractOAuth2TokenService() {
		this(TokenCacheConfiguration.defaultConfiguration(), Ticker.systemTicker(), false);
	}

	/**
	 * Constructor used to overwrite the default cache configuration.
	 *
	 * @param tokenCacheConfiguration
	 *            the cache configuration used to configure the cache.
	 */
	public AbstractOAuth2TokenService(TokenCacheConfiguration tokenCacheConfiguration) {
		this(tokenCacheConfiguration, Ticker.systemTicker(), false);

	}

	/**
	 * This constructor is used for testing purposes only.
	 *
	 * @param tokenCacheConfiguration
	 *            sets the cache configuration used to configure or disable the
	 *            cache.
	 * @param cacheTicker
	 *            will be used in the cache to determine the time.
	 * @param sameThreadCache
	 *            set to true disables maintenance jobs of the cache. This makes the
	 *            cache slower but more predictable for testing.
	 */
	AbstractOAuth2TokenService(TokenCacheConfiguration tokenCacheConfiguration, Ticker cacheTicker,
			boolean sameThreadCache) {
		Assertions.assertNotNull(tokenCacheConfiguration, "cacheConfiguration is required");
		this.tokenCacheConfiguration = tokenCacheConfiguration;
		this.responseCache = createResponseCache(cacheTicker, sameThreadCache);
		if (isCacheDisabled()) {
			LOGGER.debug("Configured token service with cache disabled");
		} else {
			LOGGER.debug("Configured token service with {}", tokenCacheConfiguration);
		}
	}

	@Override
	public void clearCache() {
		responseCache.invalidateAll();
	}

	@Override
	@Nonnull
	public TokenCacheConfiguration getCacheConfiguration() {
		return tokenCacheConfiguration;
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_CLIENT_CREDENTIALS)
				.withClientCredentials(clientCredentials)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpointUri, headers, parameters, subdomain, disableCacheForRequest);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials, @Nonnull String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");
		assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_USER_TOKEN)
				.withClientId(clientCredentials.getId())
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithAuthorizationBearerHeader(token);

		return getOAuth2TokenResponse(tokenEndpointUri, headers, parameters, subdomain, false);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nonnull String refreshToken, String subdomain, boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");
		assertNotNull(refreshToken, "refreshToken is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_REFRESH_TOKEN)
				.withRefreshToken(refreshToken)
				.withClientCredentials(clientCredentials)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpointUri, headers, parameters, subdomain, disableCacheForRequest);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(@Nonnull URI tokenEndpoint,
			@Nonnull ClientCredentials clientCredentials, @Nonnull String username, @Nonnull String password,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(username, "username is required");
		assertNotNull(password, "password is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_PASSWORD)
				.withUsername(username)
				.withPassword(password)
				.withClientCredentials(clientCredentials)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpoint, headers, parameters, subdomain, disableCacheForRequest);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpoint,
			ClientCredentials clientCredentials, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER)
				.withClientCredentials(clientCredentials)
				.withToken(token)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpoint, headers, parameters, subdomain, disableCacheForRequest);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpoint,
			ClientCredentials clientCredentials, @Nonnull String token,
			@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest,
			@Nonnull String zoneId)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(token, "token is required");
		assertNotNull(zoneId, "ZoneId is required to create X-zid header");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER)
				.withClientCredentials(clientCredentials)
				.withToken(token)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader().withHeader(HttpHeaders.X_ZID,
				zoneId);

		if (isCacheDisabled() || disableCacheForRequest) {
			return requestAccessToken(tokenEndpoint, headers, parameters);
		}
		return getOrRequestAccessToken(tokenEndpoint, headers, parameters);
	}

	/**
	 * Implements the HTTP client specific logic to perform an HTTP request and
	 * handle the response.
	 *
	 * @param tokenEndpointUri
	 *            the URI of the token endpoint the request must be sent to.
	 * @param headers
	 *            the HTTP headers that must be sent with the request.
	 * @param parameters
	 *            a map of request parameters that must be sent with the request.
	 * @return the token response.
	 * @throws OAuth2ServiceException
	 *             when the request ot the token endpoint fails or returns an error
	 *             code.
	 */
	protected abstract OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException;

	private OAuth2TokenResponse getOAuth2TokenResponse(@Nonnull URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> additionalParameters,
			@Nullable String subdomain, boolean disableCacheForRequest) throws OAuth2ServiceException {
		URI tokenEndpointUriWithSubdomainReplaced = UriUtil.replaceSubdomain(tokenEndpointUri, subdomain);
		if (isCacheDisabled() || disableCacheForRequest) {
			return requestAccessToken(tokenEndpointUriWithSubdomainReplaced, headers, additionalParameters);
		}
		return getOrRequestAccessToken(tokenEndpointUriWithSubdomainReplaced, headers, additionalParameters);
	}

	private OAuth2TokenResponse getOrRequestAccessToken(URI tokenEndpoint, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException {
		LOGGER.debug("Token was requested for endpoint uri={} with headers={} and parameters={}", tokenEndpoint,
				headers, parameters);
		CacheKey cacheKey = new CacheKey(tokenEndpoint, parameters);
		OAuth2TokenResponse oAuth2TokenResponse = responseCache.getIfPresent(cacheKey);
		if (oAuth2TokenResponse == null) {
			LOGGER.debug("Token not found in cache, requesting a new one");
			getAndCacheToken(cacheKey, headers);
		} else {
			LOGGER.debug("The token was found in cache");
			// check if token in cache should be refreshed
			Duration delta = getCacheConfiguration().getTokenExpirationDelta();
			Instant expiration = oAuth2TokenResponse.getExpiredAt().minus(delta);
			if (expiration.isBefore(Instant.now(getClock()))) {
				// refresh (soon) expired token
				LOGGER.debug("The cached token needs to be refreshed, requesting a new one");
				getAndCacheToken(cacheKey, headers);
			}
		}
		OAuth2TokenResponse response = responseCache.getIfPresent(cacheKey);
		logDebug(response);
		return response;
	}

	private void logDebug(OAuth2TokenResponse response) {
		if (!LOGGER.isDebugEnabled()) {
			return;
		}
		try {
			DecodedJwt decodedJwt = response.getDecodedAccessToken();
			LOGGER.debug("Access token: {}", decodedJwt);
		} catch (IllegalArgumentException e) {
			LOGGER.debug("Access token can not be logged. {}", e.getMessage());
		}
	}

	/**
	 * By default {@link Clock#systemUTC()} is used to determine of a cached token
	 * has reached its expiration (exp) point in time. This method can be overridden
	 * for testing purposes.
	 *
	 * @return the {@link Clock}
	 */
	protected Clock getClock() {
		return Clock.systemUTC();
	}

	private void getAndCacheToken(CacheKey cacheKey, HttpHeaders headers) throws OAuth2ServiceException {
		responseCache.put(cacheKey,
				requestAccessToken(cacheKey.tokenEndpointUri, headers, cacheKey.parameters));
	}

	private boolean isCacheDisabled() {
		return getCacheConfiguration().isCacheDisabled();
	}

	private Cache<CacheKey, OAuth2TokenResponse> createResponseCache(Ticker cacheTicker, boolean sameThreadCache) {
		Caffeine<Object, Object> cacheBuilder = Caffeine.newBuilder()
				.maximumSize(getCacheConfiguration().getCacheSize())
				.ticker(cacheTicker)
				.expireAfterWrite(getCacheConfiguration().getCacheDuration());
		if (sameThreadCache) {
			cacheBuilder.executor(Runnable::run);
		}
		if (getCacheConfiguration().isCacheStatisticsEnabled()) {
			cacheBuilder.recordStats();
		}
		return cacheBuilder.build();
	}

	@Override
	public Object getCacheStatistics() {
		return getCacheConfiguration().isCacheStatisticsEnabled() ? responseCache.stats() : null;
	}

	private class CacheKey {

		private final URI tokenEndpointUri;
		private final Map<String, String> parameters;

		public CacheKey(URI tokenEndpointUri, Map<String, String> parameters) {
			this.tokenEndpointUri = tokenEndpointUri;
			this.parameters = parameters;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o)
				return true;
			if (o == null || getClass() != o.getClass())
				return false;
			CacheKey cacheKey = (CacheKey) o;
			return Objects.equals(tokenEndpointUri, cacheKey.tokenEndpointUri) &&
					Objects.equals(parameters, cacheKey.parameters);
		}

		@Override
		public int hashCode() {
			return Objects.hash(tokenEndpointUri, parameters);
		}

		@Override
		public String toString() {
			return "CacheKey{" +
					"tokenEndpointUri=" + tokenEndpointUri +
					", parameters=" + parameters +
					'}';
		}
	}

}
