/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.DummyXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { XsuaaAutoConfiguration.class, DummyXsuaaServiceConfiguration.class })
public class XsuaaAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(XsuaaAutoConfiguration.class));
	private static String cert;
	private static String key;

	@Autowired
	private ApplicationContext context;

	@BeforeEach
	public void setup() throws IOException {
		cert = IOUtils.resourceToString("/certificate.txt", StandardCharsets.UTF_8);
		key = IOUtils.resourceToString("/key.txt", StandardCharsets.UTF_8);
	}

	@Test
	public void configures_xsuaaServiceConfiguration() {
		contextRunner.withClassLoader(new FilteredClassLoader(CloseableHttpClient.class))
				.run((context) -> {
					assertThat(context).hasSingleBean(XsuaaServiceConfigurationDefault.class);
					assertThat(context).hasBean("xsuaaServiceConfiguration");
				});
	}

	@Test
	public void configures_xsuaaRestTemplate() {
		assertThat(context.getBean("xsuaaRestOperations")).isNotNull();
		assertThat(context.getBean("xsuaaRestOperations")).isInstanceOf(RestOperations.class);
		assertThat(context.getBean(RestOperations.class)).isNotNull();
	}

	@Test
	public void configures_xsuaaRestTemplateWithInstanceSecret() {
		contextRunner
				.withPropertyValues("xsuaa.credential-type:instance-secret")
				.run((context) -> {
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).hasBean("xsuaaRestOperations");
				});
	}

	@Test
	public void configures_xsuaaRestTemplateWithBindingSecret() {
		contextRunner
				.withPropertyValues("xsuaa.credential-type:binding-secret")
				.run((context) -> {
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).hasBean("xsuaaRestOperations");
				});
	}

	@Test
	public void configures_xsuaaMtlsRestTemplateWithCredType() {
		contextRunner
				.withPropertyValues("spring.xsuaa.flows.auto:true")
				.withPropertyValues("xsuaa.credential-type:x509")
				.withPropertyValues("xsuaa.clientid:client")
				.withPropertyValues("xsuaa.certificate:" + cert)
				.withPropertyValues("xsuaa.key:" + key)
				.withPropertyValues("xsuaa.certurl:https://domain.cert.authentication.sap.com")
				.run((context) -> {
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).hasBean("xsuaaMtlsRestOperations");
				});
	}

	@Test
	public void configures_xsuaaMtlsRestTemplate() {
		contextRunner
				.withPropertyValues("xsuaa.clientid:client")
				.withPropertyValues("xsuaa.certificate:" + cert)
				.withPropertyValues("xsuaa.key:" + key)
				.withPropertyValues("xsuaa.certurl:https://domain.cert.authentication.sap.com")
				.run((context) -> {
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).hasBean("xsuaaMtlsRestOperations");
				});
	}

	@Test
	public void configures_xsuaaServiceConfiguration_withProperties() {
		contextRunner.withClassLoader(new FilteredClassLoader(CloseableHttpClient.class))
				.withPropertyValues("spring.xsuaa.auto:true")
				.withPropertyValues("spring.xsuaa.disable-default-property-source:false")
				.withPropertyValues("spring.xsuaa.multiple-bindings:false").run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(true));
					assertThat(context.getBean("xsuaaServiceConfiguration"),
							instanceOf(XsuaaServiceConfigurationDefault.class));
					assertThat(context.getBean(XsuaaServiceConfiguration.class), is(not(nullValue())));

					assertThat(context).hasSingleBean(RestTemplate.class);
				});
	}

	@Test
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.auto:false").run((context) -> {
			assertThat(context).doesNotHaveBean(RestTemplate.class);
			assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
		});
	}

	@Test
	public void serviceConfigurationDisabledByMultipleBindingsProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.multiple-bindings:true")
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration"));
	}

	@Test
	public void serviceConfigurationDisabled_DisableDefaultPropertySourceProperty_mtls() {
		contextRunner.withPropertyValues("spring.xsuaa.disable-default-property-source:true")
				.withPropertyValues("xsuaa.credential-type:x509")
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration")
						.doesNotHaveBean("mtlsRestOperations"));
	}

	@Test
	public void serviceConfigurationDisabled_DisableDefaultPropertySourceProperty_nonMtls() {
		contextRunner.withPropertyValues("spring.xsuaa.disable-default-property-source:true")
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration")
						.doesNotHaveBean("xsuaaRestOperations"));
	}

	@Test
	public void autoConfigurationInactive_if_noJwtOnClasspath() {
		contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // removes Jwt.class from classpath
				.run((context) -> {
					assertThat(context).doesNotHaveBean("xsuaaServiceConfiguration");
					assertThat(context).doesNotHaveBean("xsuaaTokenDecoder");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
				});
	}

	@Test
	public void userConfiguration_overrides_defaultBeans() {
		contextRunner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertThat(context).hasSingleBean(DummyXsuaaServiceConfiguration.class);
					assertThat(context).doesNotHaveBean(XsuaaServiceConfigurationDefault.class);
					assertThat(context).hasBean("userDefinedServiceConfiguration");

					assertThat(context).hasSingleBean(RestTemplate.class);
					assertThat(context).hasBean("userDefinedXsuaaRestOperations");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
				});
	}

	@Test
	public void userConfiguration_overrides_defaultMtlsRestTemplate() {
		contextRunner
				.withUserConfiguration(UserConfiguration.class)
				.withPropertyValues("xsuaa.credential-type:x509")
				.run((context) -> {
					assertThat(context.getEnvironment().getProperty("xsuaa.credential-type")).isEqualTo("x509");
					assertThat(context).hasSingleBean(RestOperations.class);
					assertThat(context).doesNotHaveBean("xsuaaMtlsRestOperations");
					assertThat(context).doesNotHaveBean("xsuaaRestOperations");
					assertThat(context).hasBean("userDefinedXsuaaRestOperations");
				});
	}

	@Configuration
	public static class UserConfiguration {
		@Bean
		public RestTemplate userDefinedXsuaaRestOperations() {
			return new RestTemplate();
		}

		@Bean
		public XsuaaServiceConfiguration userDefinedServiceConfiguration() {
			return new DummyXsuaaServiceConfiguration();
		}
	}
}
