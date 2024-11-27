/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.github.benmanes.caffeine.cache.Ticker;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OAuth2TokenKeyServiceWithCacheTest {

	public static final TokenKeyCacheConfiguration CACHE_CONFIGURATION = TokenKeyCacheConfiguration
			.defaultConfiguration();

	OAuth2TokenKeyServiceWithCache cut;
	OAuth2TokenKeyService tokenKeyServiceMock;
	URI TOKEN_KEYS_URI = URI.create("https://myauth.com/jwks_uri");
	private final OAuth2TokenKeyServiceWithCache.KeyParameters keyParameters = new OAuth2TokenKeyServiceWithCache.KeyParameters(
			JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
	private static final String APP_TID = "app_tid";
	private TestCacheTicker testCacheTicker;
	private static final String CLIENT_ID = "client_id";
	private static final String AZP = "azp";
	private static final Map<String, String> PARAMS = Map.of(
			HttpHeaders.X_APP_TID, APP_TID,
			HttpHeaders.X_CLIENT_ID, CLIENT_ID,
			HttpHeaders.X_AZP, AZP);

	@BeforeEach
	public void setup() throws IOException {
		tokenKeyServiceMock = mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		testCacheTicker = new TestCacheTicker();
		cut = createCut(CACHE_CONFIGURATION);
	}

	@Test
	public void getFreshInstance() {
		assertThat(cut).isNotSameAs(OAuth2TokenKeyServiceWithCache.getInstance());
	}

	@Test
	public void changeCacheConfiguration() {
		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofSeconds(678), 1234, false));

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(1234);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(Duration.ofSeconds(678));
	}

	@Test
	public void changeCacheConfiguration_valuesTooLow_leftUnchanged() {
		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();
		int oldCacheSize = cut.getCacheConfiguration().getCacheSize();

		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofSeconds(1), 1, false));

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(oldCacheSize);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void changeCacheConfiguration_tooLongDuration_leftUnchanged() {
		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();

		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofMinutes(16), 601, false));

		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void retrieveTokenKeysUsesCorrectParams()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key1 = cut.getPublicKey(keyParameters, PARAMS);
		Map<String, String> otherParams = Map.of(HttpHeaders.X_APP_TID, "otherAppTid", HttpHeaders.X_CLIENT_ID,
				"otherClientId");
		PublicKey key2 = cut.getPublicKey(keyParameters, otherParams);

		assertThat(String.valueOf(key1.getAlgorithm())).isEqualTo("RSA");
		assertThat(String.valueOf(key2.getAlgorithm())).isEqualTo("RSA");
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(TOKEN_KEYS_URI, PARAMS);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(TOKEN_KEYS_URI, otherParams);
	}

	@Test
	public void getCachedTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(keyParameters, PARAMS);
		PublicKey cachedKey = cut.getPublicKey(keyParameters, PARAMS);

		assertThat(cachedKey).isNotNull().isSameAs(key);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(PARAMS));
	}

	@Test
	public void requestFails_throwsException() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), anyMap()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));

		assertThatThrownBy(() -> cut.getPublicKey(
				keyParameters, PARAMS))
				.isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Currently unavailable");
	}

	@Test
	public void retrieveTokenKeys_afterCacheWasCleared()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(keyParameters, PARAMS);
		cut.clearCache();
		PublicKey cachedKey = cut.getPublicKey(keyParameters, PARAMS);

		assertThat(cachedKey).isNotNull();
		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(PARAMS));
	}

	@Test
	public void getCachedTokenKeys_noAppTid_noAzp()
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		Map<String, String> params = Map.of(HttpHeaders.X_CLIENT_ID, CLIENT_ID);
		when(tokenKeyServiceMock.retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(params)))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));
		PublicKey key = cut.getPublicKey(keyParameters, params);
		PublicKey cachedKey = cut.getPublicKey(keyParameters, params);

		assertThat(cachedKey).isNotNull().isSameAs(key);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(params));
	}

	@Test
	public void retrieveTokenKeys_doesRequestKeysAgainAfterCacheExpired()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(keyParameters, PARAMS);
		testCacheTicker.advance(CACHE_CONFIGURATION.getCacheDuration()); // just expired
		cut.getPublicKey(keyParameters, PARAMS);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(PARAMS));
	}

	@Test
	public void cacheStatistics_isDisabled_statisticsObjectIsNull() {
		cut = createCut(TokenKeyCacheConfiguration
				.getInstance(CACHE_CONFIGURATION.getCacheDuration(), CACHE_CONFIGURATION.getCacheSize(), false));

		assertThat(cut.getCacheStatistics()).isNull();
	}

	@Test
	public void cacheStatistics_isEnabled_returnsStatisticsObject() {
		cut = createCut(TokenKeyCacheConfiguration
				.getInstance(CACHE_CONFIGURATION.getCacheDuration(), CACHE_CONFIGURATION.getCacheSize(), true));

		assertThat(cut.getCacheStatistics()).isInstanceOf(CacheStats.class);
	}

	@Test
	public void retrieveTokenKeysForNewKeyId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(keyParameters, PARAMS);
		cut.getPublicKey(new OAuth2TokenKeyServiceWithCache.KeyParameters(JwtSignatureAlgorithm.RS256, "key-id-1",
				TOKEN_KEYS_URI), PARAMS);

		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(PARAMS));
	}

	@Test
	public void retrieveTokenKeysDoesNotCacheOnServerException()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		Map<String, String> invalidParams = Map.of(HttpHeaders.X_APP_TID, "invalidAppTid");
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), eq(invalidParams)))
				.thenThrow(new OAuth2ServiceException("Invalid parameters provided"));
		cut.getPublicKey(keyParameters, PARAMS);

		assertThatThrownBy(
				() -> cut.getPublicKey(keyParameters, invalidParams))
				.isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Invalid");

		assertThatThrownBy(
				() -> cut.getPublicKey(keyParameters, invalidParams))
				.isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Invalid");

		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(PARAMS));
		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(invalidParams));
	}

	@Test
	public void retrieveTokenKeysForNewEndpoint()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(keyParameters, PARAMS);
		cut.getPublicKey(new OAuth2TokenKeyServiceWithCache.KeyParameters(JwtSignatureAlgorithm.RS256, "key-id-0",
				URI.create("http://another/url")), PARAMS);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(PARAMS));
	}

	private OAuth2TokenKeyServiceWithCache createCut(TokenKeyCacheConfiguration cacheConfiguration) {
		return OAuth2TokenKeyServiceWithCache
				.getInstance(testCacheTicker)
				.withTokenKeyService(tokenKeyServiceMock)
				.withCacheConfiguration(cacheConfiguration);
	}

	private class TestCacheTicker implements Ticker {
		long elapsed = 0;

		@Override
		public long read() {
			return elapsed;
		}

		public void advance(Duration duration) {
			this.elapsed = elapsed + duration.toNanos();
		}
	}
}
