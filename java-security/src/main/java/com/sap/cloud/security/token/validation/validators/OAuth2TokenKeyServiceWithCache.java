/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up before the identity service is requested
 * via http.
 */
class OAuth2TokenKeyServiceWithCache implements Cacheable {
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenKeyServiceWithCache.class);

	private OAuth2TokenKeyService tokenKeyService;
	private Cache<String, JsonWebKeySet> cache;
	private CacheConfiguration cacheConfiguration = TokenKeyCacheConfiguration.defaultConfiguration();
	private Ticker cacheTicker;

	private OAuth2TokenKeyServiceWithCache() {
		// use getInstance factory method
	}

	/**
	 * Creates a new instance.
	 *
	 * @return the new instance.
	 */
	public static OAuth2TokenKeyServiceWithCache getInstance() {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = Ticker.systemTicker();
		return instance;
	}

	/**
	 * Creates a new instance and sets the cache ticker. This is used for testing.
	 *
	 * @param cacheTicker
	 * 		ticker the cache uses to determine time
	 * @return the new instance.
	 */
	static OAuth2TokenKeyServiceWithCache getInstance(Ticker cacheTicker) {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = cacheTicker;
		return instance;
	}

	/**
	 * Configures the token key cache. Use {@link TokenKeyCacheConfiguration#getInstance(Duration, int, boolean)} to
	 * pass a custom configuration.
	 * <p>
	 * Note that the cache size must be 1000 or more and the cache duration must be at least 600 seconds!
	 *
	 * @param cacheConfiguration
	 * 		the cache configuration
	 * @return this tokenKeyServiceWithCache
	 */
	public OAuth2TokenKeyServiceWithCache withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		this.cacheConfiguration = getCheckedConfiguration(cacheConfiguration);
		LOGGER.debug(
				"Configured token key cache with cacheDuration={} seconds, cacheSize={} and statisticsRecording={}",
				getCacheConfiguration().getCacheDuration().getSeconds(), getCacheConfiguration().getCacheSize(),
				getCacheConfiguration().isCacheStatisticsEnabled());
		return this;
	}

	/**
	 * Overwrites the service to be used to request the Json web keys.
	 *
	 * @param tokenKeyService
	 * 		the service to request the json web key set.
	 * @return this
	 */
	public OAuth2TokenKeyServiceWithCache withTokenKeyService(OAuth2TokenKeyService tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI of the identity service.
	 *
	 * @param keyParameters
	 * 		public key parameters such as Key Algorithm, Key ID, Key URI
	 * @param requestParameters
	 * 		additional parameters that are sent along with the request. Use constants from {@link HttpHeaders} for the
	 * 		parameter keys.
	 * @return a PublicKey
	 * @throws OAuth2ServiceException
	 * 		in case the call to the jwks endpoint of the identity service failed.
	 * @throws InvalidKeySpecException
	 * 		in case the PublicKey generation for the json web key failed.
	 * @throws NoSuchAlgorithmException
	 * 		in case the algorithm of the json web key is not supported.
	 */
	public PublicKey getPublicKey(KeyParameters keyParameters, Map<String, String> requestParameters)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyParameters.keyAlgorithm(), "keyAlgorithm must not be null.");
		assertHasText(keyParameters.keyId(), "keyId must not be null.");
		assertNotNull(keyParameters.keyUri(), "keyUrl must not be null.");

		CacheKey cacheKey = new CacheKey(keyParameters.keyUri(), requestParameters);
		return getPublicKey(keyParameters, requestParameters, cacheKey);
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI of the identity service.
	 *
	 * @param keyParameters
	 * 		public key parameters such as Key Algorithm, Key ID, Key URI
	 * @param requestParameters
	 * 		additional parameters that are sent along with the request. Use constants from {@link HttpHeaders} for the
	 * 		parameter keys.
	 * @param cacheKey
	 * 		Parameters that should be used as a key for public key cache
	 * @return a PublicKey
	 * @throws OAuth2ServiceException
	 * 		in case the call to the jwks endpoint of the identity service failed.
	 * @throws InvalidKeySpecException
	 * 		in case the PublicKey generation for the json web key failed.
	 * @throws NoSuchAlgorithmException
	 * 		in case the algorithm of the json web key is not supported.
	 */
	public PublicKey getPublicKey(KeyParameters keyParameters, Map<String, String> requestParameters,
			CacheKey cacheKey) throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyParameters.keyAlgorithm(), "keyAlgorithm must not be null.");
		assertHasText(keyParameters.keyId(), "keyId must not be null.");
		assertNotNull(keyParameters.keyUri(), "keyUrl must not be null.");

		// using an array to remember OAuth exceptions in lambda because variable needs to be effectively final
		OAuth2ServiceException[] oAuthException = new OAuth2ServiceException[1];
		JsonWebKeySet jwks = getCache().get(cacheKey.toString(), k -> {
			try {
				return retrieveTokenKeys(cacheKey, requestParameters);
			} catch (OAuth2ServiceException e) {
				oAuthException[0] = e;
				return null;
			}
		});

		if(oAuthException[0] != null) {
			throw oAuthException[0];
		}

		if (jwks.getAll().isEmpty()) {
			LOGGER.error("Retrieved no token keys from {} for the given header parameters.", keyParameters.keyUri);
			return null;
		}

		for (JsonWebKey jwk : jwks.getAll()) {
			if (keyParameters.keyId.equals(jwk.getId()) && jwk.getKeyAlgorithm().equals(keyParameters.keyAlgorithm)) {
				return jwk.getPublicKey();
			}
		}

		LOGGER.warn("No matching key found. Cached keys: {}", jwks);
		throw new IllegalArgumentException("Key with kid " + keyParameters.keyId + " not found in JWKS.");
	}

	private JsonWebKeySet retrieveTokenKeys(CacheKey cacheKey, Map<String, String> params)
			throws OAuth2ServiceException {
		String jwksJson = getTokenKeyService().retrieveTokenKeys(cacheKey.keyUri(), params);

		return JsonWebKeySetFactory.createFromJson(jwksJson);
	}

	private TokenKeyCacheConfiguration getCheckedConfiguration(CacheConfiguration cacheConfiguration) {
		Assertions.assertNotNull(cacheConfiguration, "CacheConfiguration must not be null!");
		int size = cacheConfiguration.getCacheSize();
		Duration duration = cacheConfiguration.getCacheDuration();
		if (size < 1000) {
			int currentSize = getCacheConfiguration().getCacheSize();
			LOGGER.error("Tried to set cache size to {} but the cache size must be 1000 or more."
					+ " Cache size will remain at: {}", size, currentSize);
			size = currentSize;
		}
		if (duration.getSeconds() < 600) {
			Duration currentDuration = getCacheConfiguration().getCacheDuration();
			LOGGER.error(
					"Tried to set cache duration to {} seconds but the cache duration must be at least 600 seconds."
							+ " Cache duration will remain at: {} seconds",
					duration.getSeconds(), currentDuration.getSeconds());
			duration = currentDuration;
		}
		if (duration.getSeconds() > 900) {
			Duration currentDuration = getCacheConfiguration().getCacheDuration();
			LOGGER.error(
					"Tried to set cache duration to {} seconds but the cache duration must be maximum 900 seconds."
							+ " Cache duration will remain at: {} seconds",
					duration.getSeconds(), currentDuration.getSeconds());
			duration = currentDuration;
		}
		return TokenKeyCacheConfiguration.getInstance(duration, size, cacheConfiguration.isCacheStatisticsEnabled());
	}

	private Cache<String, JsonWebKeySet> getCache() {
		if (cache == null) {
			Caffeine<Object, Object> cacheBuilder = Caffeine.newBuilder()
					.ticker(cacheTicker)
					.refreshAfterWrite(getCacheConfiguration().getCacheDuration().dividedBy(2))
					.expireAfterWrite(getCacheConfiguration().getCacheDuration())
					.maximumSize(getCacheConfiguration().getCacheSize());
			if (getCacheConfiguration().isCacheStatisticsEnabled()) {
				cacheBuilder.recordStats();
			}
			cache = cacheBuilder.build();
		}
		return cache;
	}

	private OAuth2TokenKeyService getTokenKeyService() {
		if (tokenKeyService == null) {
			this.tokenKeyService = new DefaultOAuth2TokenKeyService();
		}
		return tokenKeyService;
	}

	@Nonnull
	@Override
	public CacheConfiguration getCacheConfiguration() {
		return cacheConfiguration;
	}

	@Override
	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

	@Override
	public Object getCacheStatistics() {
		return getCacheConfiguration().isCacheStatisticsEnabled() ? getCache().stats() : null;
	}

	record CacheKey(URI keyUri, Map<String, String> params) {
		@Override
		public String toString() {
			// e.g. app_tid:<app_tid>|client_id:<client_id>|azp:<azp>
			String paramString = params.entrySet().stream()
					.filter(e -> e.getValue() != null)
					.map(e -> e.getKey() + ":" + e.getValue())
					.collect(Collectors.joining("|"));

			// e.g. url:<url>|app_tid:<app_tid>|client_id:<client_id>|azp:<azp>
			return String.format("url:%s|%s", keyUri, paramString);
		}
	}

	record KeyParameters(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri) {
	}
}
