/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThat;

public class RSAKeysTest {

	@Test
	public void generate() {
		RSAKeys keys = RSAKeys.generate();

		assertThat(keys.getPrivate()).isNotNull();
		assertThat(keys.getPublic()).isNotNull();
	}

	@Test
	public void fromKeyFiles() throws IOException, InvalidKeySpecException,
			NoSuchAlgorithmException {
		RSAKeys keys = RSAKeys.fromKeyFiles("/publicKey.txt", "/privateKey.txt");

		assertThat(keys.getPrivate()).isNotNull();
		assertThat(keys.getPublic()).isNotNull();
	}
}
