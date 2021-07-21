/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.net.URI;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { TestConfiguration.class })
@EnableConfigurationProperties(value = XsuaaServiceConfigurationDefault.class)
@TestPropertySource("/vcap.json")
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

	@Value("${xsuaa.credentialtype:}")
	public String credentialType;

	@Value("${xsuaa.certurl:}")
	public String certUrl;
}