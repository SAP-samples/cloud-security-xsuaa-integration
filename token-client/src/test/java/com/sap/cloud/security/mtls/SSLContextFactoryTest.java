/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.mtls;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

public class SSLContextFactoryTest {
	SSLContextFactory cut;
	String rsaPrivateKey;
	String certificates;

	@Before
	public void setup() throws IOException {
		cut = SSLContextFactory.getInstance();

		assertThat(cut, is(SSLContextFactory.getInstance())); // singleton

		rsaPrivateKey = readFromFile("/privateRSAKey.txt");
		certificates = readFromFile("/certificates.txt");
	}

	@Test
	public void create_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.create(null, rsaPrivateKey);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("x509Certificate");

		assertThatThrownBy(() -> {
			cut.create(certificates, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("rsaPrivateKey");

		assertThatThrownBy(() -> {
			cut.create(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(() -> {
			cut.create(new ClientCredentials("clientId", "clientSecret"));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(() -> {
			cut.create(new ClientCredentials(null, "clientSecret"));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");
	}

	@Test
	/**
	 * TODO: Certificates and key are going to expire at Thu Sep 17 06:28:03 UTC
	 * 2020 !!!
	 */
	public void create() throws GeneralSecurityException, IOException {
		assertThat(cut.create(certificates, rsaPrivateKey), is(notNullValue()));
	}

	@Test
	public void createKeyStore() throws GeneralSecurityException, IOException {
		assertThat(cut.createKeyStore(new ClientCertificate(certificates, rsaPrivateKey, null)), is(notNullValue()));
	}

	@Test
	public void createKeyStore_throwsOnNullValues() throws GeneralSecurityException, IOException {
		assertThatThrownBy(() -> {
			cut.createKeyStore(new ClientCredentials("clientId", "clientSecret"));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(() -> {
			cut.createKeyStore(new ClientCredentials(null, "clientSecret"));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");
	}

	private String readFromFile(String file) throws IOException {
		return IOUtils.resourceToString(file, StandardCharsets.UTF_8);
	}

}
