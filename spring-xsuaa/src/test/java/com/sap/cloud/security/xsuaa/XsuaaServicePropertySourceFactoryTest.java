/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.net.URI;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { TestConfiguration.class, XsuaaServiceConfigurationDefault.class })
public class XsuaaServicePropertySourceFactoryTest {

	@Autowired
	TestConfiguration testConfiguration;

	@Autowired
	XsuaaServiceConfigurationDefault serviceConfiguration;

	@Test
	public void testXsuaaServiceConfiguration() {
		assertEquals("xs2.usertoken", serviceConfiguration.getClientId());
		assertEquals("secret", serviceConfiguration.getClientSecret());
		assertEquals("https://auth.com", serviceConfiguration.getUaaUrl());
		assertEquals("auth.com", serviceConfiguration.getUaaDomain());
		assertEquals(URI.create("https://auth.cert.com"), serviceConfiguration.getCertUrl());
		assertEquals("x509", serviceConfiguration.getCredentialType().toString());
		assertThat(testConfiguration.certificate, startsWith("-----BEGIN CERTIFICATE-----"));
		assertThat(testConfiguration.key, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
	}

	@Test
	public void testInjectedPropertyValue() {
		assertEquals("xs2.usertoken", testConfiguration.xsuaaClientId);
		assertEquals("secret", testConfiguration.xsuaaClientSecret);
		assertEquals("https://auth.com", testConfiguration.xsuaaUrl);
		assertEquals("auth.com", testConfiguration.xsuaaDomain);
		assertEquals("", testConfiguration.unknown);
		assertEquals("https://auth.cert.com", testConfiguration.certUrl);
		assertEquals("x509", testConfiguration.credentialType);
		assertThat(testConfiguration.certificate, startsWith("-----BEGIN CERTIFICATE-----"));
		assertThat(testConfiguration.key, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
	}

}

@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "/vcap.json" })
class TestConfiguration {

	@Value("${xsuaa.url:}")
	public String xsuaaUrl;

	@Value("${xsuaa.uaadomain:}")
	public String xsuaaDomain;

	@Value("${xsuaa.clientid:}")
	public String xsuaaClientId;

	@Value("${xsuaa.clientsecret:}")
	public String xsuaaClientSecret;

	@Value("${xsuaa.unknown:}")
	public String unknown;

	@Value("${xsuaa.certificate:}")
	public String certificate;

	@Value("${xsuaa.key:}")
	public String key;

	@Value("${xsuaa.credential-type:}")
	public String credentialType;

	@Value("${xsuaa.certurl:}")
	public String certUrl;
}
