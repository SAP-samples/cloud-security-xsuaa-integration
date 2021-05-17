/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(classes = { MultiXsuaaTestConfigurationFromFile.class })
class IdentityServicesPropertySourceFactoryMultiTest {

	@Autowired
	MultiXsuaaTestConfigurationFromFile configuration;

	@Test
	void testInjectedPropertyValues_multiXsuaaBindings() {
		assertEquals("client-id-broker", configuration.xsuaaBrokerClientId);
		assertEquals("client-secret-broker", configuration.xsuaaBrokerClientSecret);

		assertEquals("client-id", configuration.xsuaaClientId);
		assertEquals("client-secret", configuration.xsuaaClientSecret);
		assertEquals("http://domain.xsuaadomain", configuration.xsuaaUrl);
		assertEquals("xsuaadomain", configuration.xsuaaDomain);
		assertEquals("xsappname", configuration.xsuaaAppName);

		assertEquals("", configuration.unknown);

		assertEquals("client-id-ias", configuration.identityClientId);
		assertEquals("client-secret-ias", configuration.identityClientSecret);
		assertEquals("iasdomain", configuration.identityDomain);
	}
}

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = {
		"classpath:multipleXsuaaAndIasBindings.json" })
class MultiXsuaaTestConfigurationFromFile {

	@Value("${sap.security.services.xsuaa[0].url:}")
	public String xsuaaUrl;

	@Value("${sap.security.services.xsuaa[0].uaadomain:}")
	public String xsuaaDomain;

	@Value("${sap.security.services.xsuaa[0].clientid:}")
	public String xsuaaClientId;

	@Value("${sap.security.services.xsuaa[0].clientsecret:}")
	public String xsuaaClientSecret;

	@Value("${sap.security.services.xsuaa[0].xsappname:}")
	public String xsuaaAppName;

	@Value("${sap.security.services.xsuaa[0].unknown:}")
	public String unknown;

	@Value("${sap.security.services.xsuaa[1].clientid:}")
	public String xsuaaBrokerClientId;

	@Value("${sap.security.services.xsuaa[1].clientsecret:}")
	public String xsuaaBrokerClientSecret;

	@Value("${sap.security.services.identity.clientid:}")
	public String identityClientId;

	@Value("${sap.security.services.identity.clientsecret:}")
	public String identityClientSecret;

	@Value("${sap.security.services.identity.domain:}")
	public String identityDomain;
}
