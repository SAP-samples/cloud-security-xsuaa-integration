/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.RestTemplate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { XsuaaResourceServerJwkAutoConfiguration.class, XsuaaAutoConfiguration.class })
public class XsuaaResourceServerJwkAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private WebApplicationContextRunner contextRunner;

	@Autowired
	private ApplicationContext context;

	@BeforeEach
	public void setup() {
		contextRunner = new WebApplicationContextRunner()
				.withConfiguration(
						AutoConfigurations.of(XsuaaResourceServerJwkAutoConfiguration.class,
								XsuaaAutoConfiguration.class));
	}

	@Test
	public void autoConfigurationActive() {
		contextRunner.run((context) -> {
			assertThat(context.containsBean("xsuaaJwtDecoder"), is(true));
			assertThat(context.getBean("xsuaaJwtDecoder"), instanceOf(XsuaaJwtDecoder.class));
			assertThat(context.getBean(JwtDecoder.class), is(not(nullValue())));
			assertThat(context.getBean(JwtDecoder.class), instanceOf(XsuaaJwtDecoder.class));
		});
	}

	@Test
	public void autoConfigurationActiveInclProperties() {
		contextRunner
				.withPropertyValues("spring.xsuaa.auto:true").run((context) -> {
					assertThat(context.containsBean("xsuaaJwtDecoder"), is(true));
					assertThat(context.getBean("xsuaaJwtDecoder"), instanceOf(XsuaaJwtDecoder.class));
					assertThat(context.getBean(JwtDecoder.class), is(not(nullValue())));
				});
	}

	@Test
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.auto:false").run((context) ->
			assertThat(context.containsBean("xsuaaJwtDecoder"), is(false)));
	}

	@Test
	public void autoConfigurationWithoutXsuaaServiceConfigurationOnClasspathInactive() {
		contextRunner.withClassLoader(
						new FilteredClassLoader(Jwt.class)) // make sure Jwt.class is not on the classpath
				.run((context) ->
					assertThat(context.containsBean("xsuaaJwtDecoder"), is(false)));
	}

	@Test
	public void userConfigurationCanOverrideDefaultBeans() {
		contextRunner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertThat(context.containsBean("xsuaaJwtDecoder"), is(false));
					assertThat(context.containsBean("customJwtDecoder"), is(true));
					assertThat(context.getBean("customJwtDecoder"),
							instanceOf(NimbusJwtDecoder.class));
				});
	}

	@Test
	public void userConfigurationCanOverrideDefaultRestClientBeans() {
		contextRunner.withUserConfiguration(RestClientConfiguration.class)
				.run((context) ->
					assertThat(context.containsBean("xsuaaJwtDecoder"), is(true)));
	}

	@Test
	public void autoConfigurationDisabledWhenSpringReactorIsActive() {
		ReactiveWebApplicationContextRunner contextRunner = new ReactiveWebApplicationContextRunner()
				.withConfiguration(
						AutoConfigurations.of(XsuaaResourceServerJwkAutoConfiguration.class,
								XsuaaAutoConfiguration.class));

		contextRunner.run((context) ->
			assertThat(context.containsBean("xsuaaJwtDecoder"), is(false)));
	}

	@Configuration
	public static class UserConfiguration {

		@Bean
		public JwtDecoder customJwtDecoder() {
			return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/uaa/oauth/token_keys").build();
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
