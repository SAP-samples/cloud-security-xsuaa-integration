/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.DummyXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
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
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { XsuaaAutoConfiguration.class, XsuaaTokenFlowAutoConfiguration.class,
		DummyXsuaaServiceConfiguration.class })
public class XsuaaTokenFlowAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(
					AutoConfigurations.of(XsuaaAutoConfiguration.class, XsuaaTokenFlowAutoConfiguration.class));

	@Autowired
	private ApplicationContext context;

	@Test
	public void configures_xsuaaTokenFlows_withProperties() {
		contextRunner
				.withPropertyValues("spring.xsuaa.flows.auto:true")
				.run((context) -> {
					assertThat(context).hasSingleBean(XsuaaTokenFlows.class);
					assertThat(context).hasBean("xsuaaTokenFlows");
				});
	}

	@Test
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.flows.auto:false")
				.run((context) -> assertThat(context).doesNotHaveBean(XsuaaTokenFlows.class));
	}

	@Test
	public void autoConfigurationSkipped_without_XsuaaServiceConfiguration() {
		contextRunner.withClassLoader(new FilteredClassLoader(XsuaaServiceConfiguration.class))
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaTokenFlows"));
	}

	@Test
	public void autoConfigurationSkipped_without_RestOperations() {
		new ApplicationContextRunner()
				.withConfiguration(
						AutoConfigurations.of(XsuaaTokenFlowAutoConfiguration.class))
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaTokenFlows"));
	}

	@Test
	public void autoConfigurationInactive_if_noXsuaaTokenFlowsOnClasspath() {
		contextRunner.withClassLoader(new FilteredClassLoader(XsuaaTokenFlows.class))
				.run((context) -> assertThat(context).doesNotHaveBean("xsuaaTokenFlows"));
	}

	@Test
	public void userConfigurationCanOverrideDefaultBeans() {
		contextRunner.withUserConfiguration(XsuaaTokenFlowAutoConfigurationTest.UserConfiguration.class)
				.run((context) -> {
					assertThat(context).hasSingleBean(XsuaaTokenFlows.class);
					assertThat(context).hasBean("userDefinedXsuaaTokenFlows");
					assertThat(context).doesNotHaveBean("xsuaaTokenFlows");
				});
	}

	@Test
	public void userConfigurationCanOverrideDefaultRestClientBeans() {
		contextRunner.withUserConfiguration(XsuaaTokenFlowAutoConfigurationTest.RestClientConfiguration.class)
				.withPropertyValues("xsuaa.clientid:clientid").withPropertyValues("xsuaa.clientsecret:secret")
				.run((context) -> assertThat(context.containsBean("xsuaaTokenFlows")).isTrue());
	}

	@Configuration
	public static class UserConfiguration {
		@Bean
		public XsuaaTokenFlows userDefinedXsuaaTokenFlows(RestOperations restOperations,
				XsuaaServiceConfiguration serviceConfiguration) {
			return new XsuaaTokenFlows(new XsuaaOAuth2TokenService(restOperations),
					new XsuaaDefaultEndpoints(serviceConfiguration), new ClientCredentials("id", "secret"));
		}
	}

	@Configuration
	public static class RestClientConfiguration {

		@Bean
		public RestTemplate myRestTemplate() {
			return new RestTemplate();
		}

	}
}
