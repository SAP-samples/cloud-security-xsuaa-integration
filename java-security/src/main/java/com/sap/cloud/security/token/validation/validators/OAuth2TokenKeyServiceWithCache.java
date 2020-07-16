package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Set;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
class OAuth2TokenKeyServiceWithCache implements Cacheable {
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenKeyServiceWithCache.class);

	private OAuth2TokenKeyService tokenKeyService; // access via getter
	private Cache<String, PublicKey> cache; // access via getter
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
	 * 			ticker the cache uses to determine time
	 *
	 * @return the new instance.
	 */
	static OAuth2TokenKeyServiceWithCache getInstance(Ticker cacheTicker) {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = cacheTicker;
		return instance;
	}

	/**
	 * Caches the Json web keys. Overwrite the cache time (default: 600 seconds).
	 *
	 * @deprecated in favor of {@link #withCacheConfiguration(CacheConfiguration)}
	 * @param timeInSeconds
	 *            time to cache the signing keys
	 * @return this
	 */
	@Deprecated
	public OAuth2TokenKeyServiceWithCache withCacheTime(int timeInSeconds) {
		withCacheConfiguration(TokenKeyCacheConfiguration
				.getInstance(Duration.ofSeconds(timeInSeconds), this.cacheConfiguration.getCacheSize()));
		return this;
	}

	/**
	 * Caches the Json web keys. Overwrite the size of the cache (default: 1000).
	 *
	 * @deprecated in favor of {@link #withCacheConfiguration(CacheConfiguration)}
	 * @param size
	 *            number of cached json web keys.
	 * @return this
	 */
	@Deprecated
	public OAuth2TokenKeyServiceWithCache withCacheSize(int size) {
		withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(cacheConfiguration.getCacheDuration(), size));
		return this;
	}

	/**
	 * Configures the token key cache. Use
	 * {@link TokenKeyCacheConfiguration#getInstance(Duration, int)} to pass a
	 * custom configuration.
	 *
	 * Note that the cache size must be 1000 or more and the cache duration must be
	 * at least 600 seconds!
	 *
	 * @param cacheConfiguration
	 *            the cache configuration
	 * @return this tokenKeyServiceWithCache
	 */
	public OAuth2TokenKeyServiceWithCache withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		this.cacheConfiguration = getCheckedConfiguration(cacheConfiguration);
		LOGGER.debug("Configured token key cache with cacheDuration={} seconds and cacheSize={}",
				getCacheConfiguration().getCacheDuration().getSeconds(), getCacheConfiguration().getCacheSize());
		return this;
	}

	/**
	 * Overwrites the service to be used to request the Json web keys.
	 *
	 * @param tokenKeyService
	 *            the service to request the json web key set.
	 * @return this
	 */
	public OAuth2TokenKeyServiceWithCache withTokenKeyService(OAuth2TokenKeyService tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI
	 * of the identity service.
	 *
	 * @param keyAlgorithm
	 *            the Key Algorithm of the Access Token.
	 * @param keyId
	 *            the Key Id of the Access Token.
	 * @param keyUri
	 *            the Token Key Uri (jwks) of the Access Token (can be tenant
	 *            specific).
	 * @return a PublicKey
	 * @throws OAuth2ServiceException
	 *             in case the call to the jwks endpoint of the identity service
	 *             failed.
	 * @throws InvalidKeySpecException
	 *             in case the PublicKey generation for the json web key failed.
	 * @throws NoSuchAlgorithmException
	 *             in case the algorithm of the json web key is not supported.
	 *
	 */
	@Nullable
	public PublicKey getPublicKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyAlgorithm, "keyAlgorithm must not be null.");
		assertHasText(keyId, "keyId must not be null.");
		assertNotNull(keyUri, "keyUrl must not be null.");

		String cacheKey = getUniqueCacheKey(keyAlgorithm, keyId, keyUri);

		PublicKey publicKey = getCache().getIfPresent(cacheKey);
		if (publicKey == null) {
			retrieveTokenKeysAndFillCache(keyUri);
		}
		return getCache().getIfPresent(cacheKey);
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
		return TokenKeyCacheConfiguration.getInstance(duration, size);
	}

	private void retrieveTokenKeysAndFillCache(URI jwksUri)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(getTokenKeyService().retrieveTokenKeys(jwksUri));
		if (keySet == null) {
			return;
		}
		Set<JsonWebKey> jwks = keySet.getAll();
		for (JsonWebKey jwk : jwks) {
			getCache().put(getUniqueCacheKey(jwk.getKeyAlgorithm(), jwk.getId(), jwksUri), jwk.getPublicKey());
		}
	}

	private Cache<String, PublicKey> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder()
					.ticker(cacheTicker)
					.expireAfterWrite(cacheConfiguration.getCacheDuration())
					.maximumSize(cacheConfiguration.getCacheSize())
					.build();
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

	public static String getUniqueCacheKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI jwksUri) {
		return jwksUri + String.valueOf(JsonWebKeyImpl.calculateUniqueId(keyAlgorithm, keyId));
	}

}
