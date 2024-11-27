/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Collections;

import static com.sap.cloud.security.config.ServiceConstants.URL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class OAuth2ServiceConfigurationBuilderTest {

	private OAuth2ServiceConfigurationBuilder cut;

	@BeforeEach
	public void setUp() {
		cut = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA);
	}

	@Test
	public void forService() {
		OAuth2ServiceConfiguration configuration = cut.build();

		assertThat(configuration.getService()).isEqualTo(Service.XSUAA);
	}

	@Test
	public void forService_serviceNull_throwsException() {
		assertThatThrownBy(() -> OAuth2ServiceConfigurationBuilder.forService(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("must not be null");
	}

	@Test
	public void withClientId() {
		String clientId = "theClientId";

		OAuth2ServiceConfiguration configuration = cut.withClientId(clientId).build();

		assertThat(configuration.getClientId()).isEqualTo(clientId);
	}

	@Test
	public void withClientSecret() {
		String clientSecret = "theClientSecret";

		OAuth2ServiceConfiguration configuration = cut.withClientSecret(clientSecret).build();

		assertThat(configuration.getClientSecret()).isEqualTo(clientSecret);
	}

	@Test
	public void withCertificateAndKey() {
		String certificate = "-----BEGIN CERTIFICATE-----";
		String key = "-----BEGIN RSA PRIVATE KEY-----";
		String clientId = "myClientId";

		OAuth2ServiceConfiguration configuration = cut.withPrivateKey(key).withCertificate(certificate)
				.withClientId(clientId).build();

		assertThat(configuration.getClientIdentity().getKey()).isEqualTo(key);
		assertThat(configuration.getClientIdentity().getCertificate()).isEqualTo(certificate);
	}

	@Test
	public void withCredentialType() {
		OAuth2ServiceConfiguration configuration = cut.withCredentialType(CredentialType.X509).build();

		assertThat(configuration.getCredentialType()).isEqualTo(CredentialType.X509);
	}

	@Test
	public void withClientIdentityX509() {
		String certificate = "-----BEGIN CERTIFICATE-----";
		String key = "-----BEGIN RSA PRIVATE KEY-----";
		String clientId = "myClientId";
		ClientIdentity clientCertificate = new ClientCertificate(certificate, key, clientId);

		OAuth2ServiceConfiguration configuration = cut.withClientIdentity(clientCertificate)
				.withCredentialType(CredentialType.X509).build();
		assertThat(configuration.getClientIdentity().getKey()).isEqualTo(key);
		assertThat(configuration.getClientIdentity().getCertificate()).isEqualTo(certificate);
		assertThat(configuration.getClientId()).isEqualTo(clientId);
		assertThat(configuration.getClientIdentity()).isEqualTo(clientCertificate);
	}

	@Test
	public void withClientIdentity() {
		String clientId = "myClientId";
		String secret = "mySecret";
		ClientIdentity clientIdentity = new ClientCredentials(clientId, secret);

		OAuth2ServiceConfiguration configuration = cut.withClientIdentity(clientIdentity).build();
		assertThat(configuration.getClientId()).isEqualTo(clientId);
		assertThat(configuration.getClientSecret()).isEqualTo(secret);
		assertThat(configuration.getClientIdentity()).isEqualTo(clientIdentity);
	}

	@Test
	public void withCertUrl() {
		String url = "http://the.cert.Url.org";

		OAuth2ServiceConfiguration configuration = cut.withCertUrl(url).build();

		assertThat(configuration.getCertUrl()).isEqualTo(URI.create(url));
	}

	@Test
	public void withUrl() {
		String url = "http://theUrl.org";

		OAuth2ServiceConfiguration configuration = cut.withUrl(url).build();

		assertThat(configuration.getUrl()).isEqualTo(URI.create(url));
	}

	@Test
	public void withProperty() {
		String propertyName = "propertyName";
		String propertyValue = "value";

		OAuth2ServiceConfiguration configuration = cut.withProperty(propertyName, propertyValue).build();

		assertThat(configuration.getProperty(propertyName)).isEqualTo(propertyValue);
	}

	@Test
	public void withUrl_setViaProperty() {
		String url = "http://theUrl.org";

		OAuth2ServiceConfiguration configuration = cut.withProperty(URL, url).build();

		assertThat(configuration.getUrl()).isEqualTo(URI.create(url));
	}

	@Test
	public void equals_sameClientId() {
		OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId("client-id")
				.build();

		assertThat(cut.withClientId("client-id").build()).isEqualTo(config);
	}

	@Test
	public void notEquals_differentClientId() {
		OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId("client-id")
				.build();

		assertThat(cut.withClientId("client-id2").build()).isNotEqualTo(config);
	}

	@Test
	public void sameHashCode() {
		OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId("client-id").withClientSecret("secret")
				.build();

		assertThat(cut.withClientId("client-id").withClientSecret("secret").build())
				.hasSameHashCodeAs(config);
	}

	@Test
	public void notSameHashCode() {
		OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withClientId("client-id").withClientSecret("secret")
				.build();

		assertThat(cut.withClientId("client-id2").withClientSecret("secret-2").build().hashCode())
				.isNotEqualTo(config.hashCode());
	}

	@Test
	public void fromConfiguration_createsBuilderWithDataFromConfiguration() {
		OAuth2ServiceConfiguration baseConfiguration = cut.withClientId("base-client-id")
				.withClientSecret("base-client-secret")
				.withUrl("http://url.base")
				.withProperty("testing-key", "base-value")
				.build();

		OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder
				.fromConfiguration(baseConfiguration);
		OAuth2ServiceConfiguration configuration = builder.build();

		assertThat(configuration.getClientId()).isEqualTo("base-client-id");
		assertThat(configuration.getClientSecret()).isEqualTo("base-client-secret");
		assertThat(configuration.getUrl()).isEqualTo(URI.create("http://url.base"));
		assertThat(configuration.getCertUrl()).isNull();
		assertThat(configuration.getProperty("testing-key")).isEqualTo("base-value");
		assertThat(configuration.getDomains()).isEqualTo(Collections.EMPTY_LIST);
	}

	@Test
	public void x509IntegrationTest() {
		String url = "http://the.cert.Url.org";

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("client-id")
				.withCertUrl(url)
				.withCertificate("cert")
				.withPrivateKey("key")
				.withCredentialType(CredentialType.X509)
				.build();

		assertThat(configuration.getClientId()).isEqualTo("client-id");
		assertThat(configuration.getClientIdentity().getCertificate()).isEqualTo("cert");
		assertThat(configuration.getClientIdentity().getKey()).isEqualTo("key");
		assertThat(configuration.getUrl()).isNull();
		assertThat(configuration.getCertUrl()).isEqualTo(URI.create(url));
		assertThat(configuration.getCredentialType()).isEqualTo(CredentialType.X509);
	}
}
