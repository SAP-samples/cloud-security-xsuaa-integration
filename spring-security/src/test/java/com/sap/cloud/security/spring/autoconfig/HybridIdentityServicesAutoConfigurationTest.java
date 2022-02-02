/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.spring.token.authentication.HybridJwtDecoder;
import com.sap.cloud.security.spring.token.authentication.IasJwtDecoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HybridIdentityServicesAutoConfigurationTest {
	private final List<String> properties = new ArrayList<>();
	private WebApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		properties.add("sap.security.services.xsuaa.url:http://localhost");
		properties.add("sap.security.services.xsuaa.uaadomain:localhost");
		properties.add("sap.security.services.xsuaa.xsappname:theAppName");
		properties.add("sap.security.services.xsuaa.clientid:cid");
		properties.add("sap.security.services.identity.url:http://localhost");
		properties.add("sap.security.services.identity.clientid:cid");

		runner = new WebApplicationContextRunner()
				.withPropertyValues(properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));
	}

	@Test
	void autoConfigurationActive() {
		runner.run(context -> assertNotNull(context.getBean("hybridJwtDecoder", HybridJwtDecoder.class)));
	}

	@Test
	void autoConfigurationActiveInclProperties() {
		runner.withPropertyValues("sap.spring.security.hybrid.auto:true")
				.run((context) -> assertNotNull(context.getBean(HybridJwtDecoder.class)));
	}

	@Test
	void autoConfigurationDisabledByProperty() {
		runner.withPropertyValues("sap.spring.security.hybrid.auto:false")
				.run((context) -> assertFalse(context.containsBean("hybridJwtDecoder")));
	}

	@Test
	void autoConfigurationForIdentityAndSingleXsuaaService() {
		WebApplicationContextRunner mt_runner;

		List<String> mt_properties = new ArrayList<>();
		mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa[0].uaadomain:localhost");
		mt_properties.add("sap.security.services.xsuaa[0].xsappname:theAppName");
		mt_properties.add("sap.security.services.xsuaa[0].clientid:cid");
		mt_properties.add("sap.security.services.identity.url:http://localhost");
		mt_properties.add("sap.security.services.identity.clientid:cid");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

		mt_runner.run(context -> {
			assertFalse(context.containsBean("hybridJwtDecoder"));
			assertTrue(context.containsBean("hybridJwtDecoderMultiXsuaaServices"));
		});
	}

	@Test
	void autoConfigurationUsesDecoderForMultipleXsuaaServicesAsPrimary() {
		WebApplicationContextRunner mt_runner;

		List<String> mt_properties = new ArrayList<>(properties);
		mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa[0].uaadomain:localhost");
		mt_properties.add("sap.security.services.xsuaa[0].xsappname:theAppName");
		mt_properties.add("sap.security.services.xsuaa[0].clientid:cid");
		mt_properties.add("sap.security.services.xsuaa[1].clientid:cid2");
		mt_properties.add("sap.security.services.identity.url:http://localhost");
		mt_properties.add("sap.security.services.identity.clientid:cid");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

		mt_runner.run(context -> {
			assertTrue(context.containsBean("hybridJwtDecoder"));
			assertTrue(context.containsBean("hybridJwtDecoderMultiXsuaaServices"));
			assertNotEquals(context.getBean(HybridJwtDecoder.class), context.getBean("hybridJwtDecoder"));
			assertEquals(context.getBean(HybridJwtDecoder.class),
					context.getBean("hybridJwtDecoderMultiXsuaaServices"));
		});
	}

	@Test
	void autoConfigurationUsesDecoderForSingleXsuaaService() {
		WebApplicationContextRunner mt_runner;

		List<String> mt_properties = new ArrayList<>();
		mt_properties.add("sap.security.services.xsuaa.url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa.uaadomain:localhost");
		mt_properties.add("sap.security.services.xsuaa.xsappname:theAppName");
		mt_properties.add("sap.security.services.xsuaa.clientid:xsuaacid");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

		mt_runner.run(context -> {
			assertTrue(context.containsBean("hybridJwtDecoder"));
			assertFalse(context.containsBean("hybridJwtDecoderMultiXsuaaServices"));
			assertEquals(context.getBean(HybridJwtDecoder.class),
					context.getBean("hybridJwtDecoder"));
		});
	}

	@Test
	void autoConfigurationUsesDecoderForMultipleXsuaaServices() {
		WebApplicationContextRunner mt_runner;

		List<String> mt_properties = new ArrayList<>();
		mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
		mt_properties.add("sap.security.services.xsuaa[0].uaadomain:localhost");
		mt_properties.add("sap.security.services.xsuaa[0].xsappname:theAppName");
		mt_properties.add("sap.security.services.xsuaa[0].clientid:xsuaacid");
		mt_properties.add("sap.security.services.xsuaa[1].clientid:cid2");

		mt_runner = new WebApplicationContextRunner()
				.withPropertyValues(mt_properties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

		mt_runner.run(context -> {
			assertFalse(context.containsBean("hybridJwtDecoder"));
			assertTrue(context.containsBean("hybridJwtDecoderMultiXsuaaServices"));
			assertEquals(context.getBean(HybridJwtDecoder.class),
					context.getBean("hybridJwtDecoderMultiXsuaaServices"));
		});
	}

	@Test
	void userConfigurationCanOverrideDefaultBeans() {
		runner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertFalse(context.containsBean("hybridJwtDecoder"));
					assertNotNull(context.getBean("customJwtDecoder", NimbusJwtDecoder.class));
				});
	}

	@Test
	void autoConfigurationIdentityServiceOnly() {
		List<String> identityProperties = new ArrayList<>();
		identityProperties.add("sap.security.services.identity.url:http://localhost");
		identityProperties.add("sap.security.services.identity.domains:localhost");
		identityProperties.add("sap.security.services.identity.clientid:cid");

		WebApplicationContextRunner runner = new WebApplicationContextRunner()
				.withPropertyValues(identityProperties.toArray(new String[0]))
				.withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));
		runner.run(context -> assertNotNull(context.getBean("iasJwtDecoder", IasJwtDecoder.class)));
	}

	@Configuration
	static class UserConfiguration {

		@Bean
		public JwtDecoder customJwtDecoder() {
			return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/uaa/oauth/token_keys").build();
		}
	}

}
