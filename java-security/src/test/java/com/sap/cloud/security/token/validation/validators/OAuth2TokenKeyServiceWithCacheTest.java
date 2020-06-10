package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class OAuth2TokenKeyServiceWithCacheTest {
	OAuth2TokenKeyServiceWithCache cut;
	OAuth2TokenKeyService tokenKeyServiceMock;
	URI TOKEN_KEYS_URI = URI.create("https://myauth.com/jwks_uri");

	@Before
	public void setup() throws IOException {
		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(TOKEN_KEYS_URI))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		cut = OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock);
	}

	@Test
	public void getFreshInstance() {
		assertThat(cut).isNotSameAs(OAuth2TokenKeyServiceWithCache.getInstance());
	}

	@Test
	public void changeCacheConfiguration() {
		cut = cut.withCacheSize(1234).withCacheTime(678);

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(1234);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(Duration.ofSeconds(678));
	}

	@Test
	public void changeCacheConfiguration_valuesTooLow_leftUnchanged() {

		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();
		int oldCacheSize = cut.getCacheConfiguration().getCacheSize();

		cut = cut.withCacheSize(1).withCacheTime(1);

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(oldCacheSize);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void retrieveTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(String.valueOf(key.getAlgorithm())).isEqualTo("RSA");

		Mockito.verify(tokenKeyServiceMock, times(1))
				.retrieveTokenKeys(TOKEN_KEYS_URI);
	}

	@Test
	public void getCachedTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);

		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(cachedKey).isNotNull();
		assertThat(cachedKey).isSameAs(key);

		Mockito.verify(tokenKeyServiceMock, times(1))
				.retrieveTokenKeys(TOKEN_KEYS_URI);
	}

	@Test
	public void retrieveNoTokenKeys_returnsNull()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.withTokenKeyService(Mockito.mock(OAuth2TokenKeyService.class));
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(key).isNull();
	}

	@Test
	public void requestFails_throwsException() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));

		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Currently unavailable");
	}

	@Test
	public void retrieveTokenKeys_afterCacheWasCleared()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);

		cut.clearCache();

		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(cachedKey).isNotNull();

		Mockito.verify(tokenKeyServiceMock, times(2))
				.retrieveTokenKeys(TOKEN_KEYS_URI);
	}

	@Test
	public void retrieveTokenKeysFromAnotherEndpoint()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-1", TOKEN_KEYS_URI);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", URI.create("http://another/url"));

		Mockito.verify(tokenKeyServiceMock, times(2))
				.retrieveTokenKeys(any());
	}
}
