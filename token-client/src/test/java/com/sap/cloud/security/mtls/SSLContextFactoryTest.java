/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.mtls;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class SSLContextFactoryTest {
	SSLContextFactory cut;
	String rsaPrivateKey;
	String rsaPrivateKeyCorrupt;
	String eccPrivateKey;
	String certificates;
	String eccCertificate;

	@BeforeEach
	public void setup() throws IOException {
		cut = SSLContextFactory.getInstance();

		assertThat(cut, is(SSLContextFactory.getInstance())); // singleton

		rsaPrivateKey = readFromFile("/privateRSAKey.txt");
		rsaPrivateKeyCorrupt = readFromFile("/privateRSAKeyCorrupt.txt");
		eccPrivateKey = readFromFile("/key-ztis.pem");
		certificates = readFromFile("/certificates.txt");
		eccCertificate = readFromFile("/cert-ztis.pem");
	}

	@Test
	public void create_throwsOnNullValues() {
		assertThatThrownBy(() -> cut.create(null, rsaPrivateKey)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("x509Certificate");

		assertThatThrownBy(() -> cut.create(certificates, null)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("privateKey");

		assertThatThrownBy(() -> cut.create(null)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(() -> cut.create(new ClientCredentials("clientId", "clientSecret"))).isInstanceOf(
				IllegalArgumentException.class).hasMessageStartingWith("clientIdentity.getCertificate()");

		assertThatThrownBy(() -> cut.create(new ClientCertificate("certificate", null, null))).isInstanceOf(
				IllegalArgumentException.class).hasMessageStartingWith("clientIdentity.getKey()");
	}

	@Test
	public void create_unsupportedKey() {
		assertThatThrownBy(() -> cut.create(certificates, rsaPrivateKeyCorrupt)).isInstanceOf(
						GeneralSecurityException.class)
				.hasMessageStartingWith("Exception during parsing DER encoded private key");
	}

	@Test
	public void create() throws GeneralSecurityException, IOException {
		assertThat(cut.create(certificates, rsaPrivateKey), is(notNullValue()));
		assertThat(cut.create(eccCertificate, eccPrivateKey), is(notNullValue()));
	}

	@Test
	public void createKeyStore() throws GeneralSecurityException, IOException {
		assertThat(cut.createKeyStore(new ClientCertificate(certificates, rsaPrivateKey, null)), is(notNullValue()));
		assertThat(cut.createKeyStore(new ClientCertificate(eccCertificate, eccPrivateKey, null)), is(notNullValue()));
	}

	@Test
	public void createKeyStore_throwsOnNullValues() {
		assertThatThrownBy(() -> cut.createKeyStore(new ClientCredentials("clientId", "clientSecret"))).isInstanceOf(
				IllegalArgumentException.class).hasMessageStartingWith("clientIdentity.getCertificate()");

		assertThatThrownBy(() -> cut.createKeyStore(new ClientCertificate("certificate", null, null))).isInstanceOf(
				IllegalArgumentException.class).hasMessageStartingWith("clientIdentity.getKey()");
	}

	private String readFromFile(String file) throws IOException {
		return IOUtils.resourceToString(file, StandardCharsets.UTF_8);
	}

}
