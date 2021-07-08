/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Performance test for spring-xsuaa jwt token validation.
 */
public class SpringSecurityPerformanceIT {

	private static final Logger LOGGER = LoggerFactory.getLogger(SpringSecurityPerformanceIT.class);
	private static SecurityTest securityTest;

	@BeforeAll
	static void setUp() throws Exception {
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
		securityTest = new SecurityTest(XSUAA).setKeys("/publicKey.txt", "/privateKey.txt");
		securityTest.setup();
	}

	@AfterAll
	static void tearDown() {
		securityTest.tearDown();
	}

	@Test
	public void onlineValidation() throws Exception {
		String token = securityTest.createToken().getTokenValue();
		new JwtDecoderBuilder().withXsuaaServiceConfiguration(OAuth2ServiceConfigurationBuilder.);
		JwtDecoder jwtDecoder = createOnlineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Online validation result: {}", result.toString());
	}

	@Test
	public void offlineValidation() throws Exception {
		String token = securityTest.createToken().getTokenValue();
		JwtDecoder jwtDecoder = createOfflineJwtDecoder();
		assertThat(jwtDecoder.decode(token)).isNotNull();

		BenchmarkUtil.Result result = BenchmarkUtil.execute(() -> jwtDecoder.decode(token));
		LOGGER.info("Offline validation result: {}", result.toString());
	}

	private JwtDecoder createOnlineJwtDecoder_old() {
		//XsuaaServiceConfigurationCustom configuration = new XsuaaServiceConfigurationCustom(createXsuaaCredentials());
		//JwtDecoder jwtDecoder = new XsuaaJwtDecoderBuilder(configuration).build();
		//return jwtDecoder;
	}

	private JwtDecoder createOnlineJwtDecoder() {
		com.sap.cloud.security.spring.token.authentication.
	}
/*
	private JwtDecoder createOfflineJwtDecoder() throws IOException {
		final XsuaaCredentials xsuaaCredentials = createXsuaaCredentials();
		// Workaround because RestOperations cannot easily be switched off
		xsuaaCredentials.setUaaDomain("__nonExistingUaaDomainForOfflineTesting__");
		final String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8);
		final XsuaaServiceConfiguration xsuaaConfig = new XsuaaServiceConfigurationCustom(xsuaaCredentials) {
			@Override
			public String getVerificationKey() {
				return publicKey.replace("\n", "");
			}
		};
		return new XsuaaJwtDecoderBuilder(xsuaaConfig).build();
	}

	private XsuaaCredentials createXsuaaCredentials() {
		XsuaaCredentials xsuaaCredentials = new XsuaaCredentials();
		xsuaaCredentials.setUaaDomain(SecurityTest.DEFAULT_DOMAIN);
		xsuaaCredentials.setClientId(SecurityTest.DEFAULT_CLIENT_ID);
		xsuaaCredentials.setXsAppName(SecurityTest.DEFAULT_APP_ID);
		return xsuaaCredentials;
	}
*/
}

