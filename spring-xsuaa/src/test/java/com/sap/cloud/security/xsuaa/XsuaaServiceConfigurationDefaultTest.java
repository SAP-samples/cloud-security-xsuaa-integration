package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.CredentialType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@RunWith(SpringJUnit4ClassRunner.class)
@TestPropertySource(properties = { "xsuaa.clientid=client", "xsuaa.certificate=cert", "xsuaa.key=key",
		"xsuaa.certurl=https://my.cert.authentication.sap.com", "xsuaa.credential-type=x509" })
@ContextConfiguration(classes = { XsuaaServiceConfigurationDefault.class })
public class XsuaaServiceConfigurationDefaultTest {

	@Autowired
	XsuaaServiceConfigurationDefault cut;

	@Test
	public void getClientIdentity() {
		assertThat(cut.getClientIdentity().getCertificate()).isEqualTo("cert");
		assertThat(cut.getClientIdentity().getKey()).isEqualTo("key");
		assertThat(cut.getClientIdentity().getId()).isEqualTo("client");
		assertThat(cut.getClientIdentity().isCertificateBased()).isTrue();
	}

	@Test
	public void getClientId() {
		assertThat(cut.getClientIdentity().getId()).isEqualTo(cut.getClientId()).isEqualTo("client");
	}

	@Test
	public void getClientSecret() {
		assertThat(cut.getClientSecret()).isEmpty();
	}

	@Test
	public void getCredentialType() {
		assertThat(cut.getCredentialType()).isEqualTo(CredentialType.X509);
	}

	@Test
	public void getCertUrl() {
		assertThat(cut.getCertUrl()).isEqualTo(URI.create("https://my.cert.authentication.sap.com"));
	}

	@Test
	public void unsupportedMethods() {
		assertThatThrownBy(() -> cut.hasProperty("")).isInstanceOf(UnsupportedOperationException.class);
		assertThatThrownBy(() -> cut.getProperty("")).isInstanceOf(UnsupportedOperationException.class);
		assertThatThrownBy(() -> cut.getProperties()).isInstanceOf(UnsupportedOperationException.class);
	}
}