/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.token.validation.validators.JsonWebKey.DEFAULT_KEY_ID;
import static org.assertj.core.api.Assertions.assertThat;

public class JsonWebKeySetTest {

	public static final JsonWebKey JSON_WEB_KEY = JsonWebKeyTestFactory.create();

	private JsonWebKeySet cut;

	@BeforeEach
	public void setUp() {
		cut = new JsonWebKeySet();
	}

	@Test
	public void getKeyByAlgorithmAndId_returnsKey_whenKeyHasBeenInserted() {
		cut.put(JSON_WEB_KEY);

		assertThat(cut.getKeyByAlgorithmAndId(JSON_WEB_KEY.getKeyAlgorithm(), JSON_WEB_KEY.getId()))
				.isEqualTo(JSON_WEB_KEY);
	}

	@Test
	public void getKeyByAlgorithmAndId_returnsNull_onEmptyJSONWebKeySet() {
		assertThat(cut.getKeyByAlgorithmAndId(JSON_WEB_KEY.getKeyAlgorithm(), JSON_WEB_KEY.getId())).isNull();
	}

	@Test
	@Disabled
	public void getKeyByAlgorithmAndId_returnsNull_whenKeyTypeDoesNotMatch() {
		JwtSignatureAlgorithm differentKeyAlgorithm = JwtSignatureAlgorithm.RS256; // ES256

		cut.put(JSON_WEB_KEY);

		assertThat(cut.getKeyByAlgorithmAndId(differentKeyAlgorithm, JSON_WEB_KEY.getId())).isNull();
	}

	@Test
	public void getKeyByAlgorithmAndId_returnsDefault_whenKeyIdDoesNotMatch() {
		String differentKeyId = "differentKeyId";

		cut.put(JSON_WEB_KEY);

		assertThat(cut.getKeyByAlgorithmAndId(JSON_WEB_KEY.getKeyAlgorithm(), differentKeyId)).isNull();
	}

	@Test
	public void getKeyByAlgorithmAndId_returnsDefault_whenKeyIdMatchesDefault() {
		cut.put(JSON_WEB_KEY);

		cut.put(JsonWebKeyTestFactory.createDefault());

		String keyId = cut.getKeyByAlgorithmAndId(JSON_WEB_KEY.getKeyAlgorithm(), DEFAULT_KEY_ID).getId();
		assertThat(keyId).isEqualTo(DEFAULT_KEY_ID);
	}

	@Test
	public void getKeyByAlgorithmAndId_returnsNull_whenKeyIdDoesNotMatch() {
		cut.put(JSON_WEB_KEY);

		cut.put(JsonWebKeyTestFactory.createDefault());

		assertThat(cut.getKeyByAlgorithmAndId(JSON_WEB_KEY.getKeyAlgorithm(), "not-existing")).isNull();
	}

	@Test
	public void put_returnsTrue_whenKeyHasNotBeenInsertedYet() {
		boolean inserted = cut.put(JSON_WEB_KEY);

		assertThat(inserted).isTrue();
	}

	@Test
	public void put_returnsFalse_whenKeyIsAlreadyInserted() {
		cut.put(JSON_WEB_KEY);

		boolean inserted = cut.put(JSON_WEB_KEY);

		assertThat(inserted).isFalse();
	}

	@Test
	public void putAll_overwrites_whenKeysAreAlreadyInserted() {
		JsonWebKeySet other = new JsonWebKeySet();
		other.put(JSON_WEB_KEY);
		JsonWebKey JSON_WEB_KEY_DEFAULT = JsonWebKeyTestFactory.createDefault();
		other.put(JSON_WEB_KEY_DEFAULT);

		cut.put(JSON_WEB_KEY);

		cut.putAll(other);
		assertThat(cut.getKeyByAlgorithmAndId(JSON_WEB_KEY.getKeyAlgorithm(), JSON_WEB_KEY.getId()))
				.isEqualTo(JSON_WEB_KEY);
		assertThat(cut.getKeyByAlgorithmAndId(JSON_WEB_KEY_DEFAULT.getKeyAlgorithm(), JSON_WEB_KEY_DEFAULT.getId()))
				.isEqualTo(JSON_WEB_KEY_DEFAULT);
	}

	@Test
	public void stringify() {
		cut.put(JSON_WEB_KEY);
		assertThat(cut.toString()).isEqualTo("key-id-1(RS256)");
	}
}
