/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JsonWebKeySetFactoryTest {

	private String jsonWebTokenKeys;

	@BeforeEach
	public void setup() throws IOException {
		jsonWebTokenKeys = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void getEmptyJsonWebKeySetWhenJsonIsNull() {
		assertThat(JsonWebKeySetFactory.createFromJson(null).getAll(), equalTo(Collections.EMPTY_SET));
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "key-id-1");
		assertThat(jwk.getKeyAlgorithm().value(), equalTo("RS256"));
		assertThat(jwk.getKeyAlgorithm().type(), equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getKeyAlgorithm().type()));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getKeys() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "key-id-1");
		assertThat(jwk.getKeyAlgorithm().value(), equalTo("RS256"));
		assertThat(jwk.getKeyAlgorithm().type(), equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getKeyAlgorithm().type()));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getIasKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		jsonWebTokenKeys = IOUtils.resourceToString("/iasJsonWebTokenKeys_noKid.json", StandardCharsets.UTF_8);
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, null);
		assertThat(jwk.getKeyAlgorithm().type(), equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getKeyAlgorithm().type()));
		assertThat(jwk.getId(), equalTo(JsonWebKey.DEFAULT_KEY_ID));
	}
}
