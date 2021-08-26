/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.File;
import java.util.Map;

import static com.sap.cloud.security.config.k8s.K8sConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SystemStubsExtension.class)
class K8sServiceConfigurationResolverTest {

	private static K8sServiceConfigurationResolver cut;
	public static final String ABSOLUTE_PATH = new File("src/test/resources").getAbsolutePath();
	private static LogCaptor logCaptor;

	@BeforeAll
	static void beforeAll() {
		logCaptor = LogCaptor.forClass(K8sServiceConfigurationResolver.class);
	}

	@AfterEach
	void tearDown() {
		logCaptor.clearLogs();
	}

	@Test
	void loadServiceManagerConfig(EnvironmentVariables environmentVariables) {
		environmentVariables.set(SM_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/service-manager");
		cut = new K8sServiceConfigurationResolver();

		assertEquals("smClientId", cut.loadServiceManagerConfig().getClientId());
	}

	@Test
	void loadOauth2ServiceConfig(EnvironmentVariables environmentVariables) {
		environmentVariables.set(XSUAA_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/xsuaa");
		environmentVariables.set(IAS_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/ias");
		cut = new K8sServiceConfigurationResolver();

		assertEquals(2, cut.loadOauth2ServiceConfig(Service.XSUAA).size());
		assertEquals(2, cut.loadOauth2ServiceConfig(Service.IAS).size());
		assertEquals("xsuaaClientId",
				cut.loadOauth2ServiceConfig(Service.XSUAA).get("xsuaa-application").getClientId());
		assertEquals("xsuaaBrokerClientId",
				cut.loadOauth2ServiceConfig(Service.XSUAA).get("xsuaa-broker").getClientId());
		assertEquals("iasClientId", cut.loadOauth2ServiceConfig(Service.IAS).get("ias1").getClientId());
		assertEquals("iasClientId2", cut.loadOauth2ServiceConfig(Service.IAS).get("ias2").getClientId());
	}

	@Test
	void loadOAuth2ServiceConfig_noValidXsuaaServiceBinding(EnvironmentVariables environmentVariables) {
		environmentVariables.set(XSUAA_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/xsuaa-invalid");
		cut = new K8sServiceConfigurationResolver();
		Map<String, OAuth2ServiceConfiguration> xsuaaConfig = cut.loadOauth2ServiceConfig(Service.XSUAA);

		assertEquals(1, xsuaaConfig.size());
		assertEquals("clientId", xsuaaConfig.get("xsuaa-folder-file").getClientId());
		assertNull(xsuaaConfig.get("xsuaa-folder-file").getClientSecret());
		assertThat(logCaptor.getWarnLogs()).contains("clientid value is empty");
		assertDoesNotThrow(() -> cut.loadOauth2ServiceConfig(Service.XSUAA));
	}

	@Test
	void loadOAuth2ServiceConfig_noIasServiceBinding(EnvironmentVariables environmentVariables) {
		environmentVariables.set(IAS_CONFIG_PATH, "/no/path");
		cut = new K8sServiceConfigurationResolver();
		Map<String, OAuth2ServiceConfiguration> iasConfig = cut.loadOauth2ServiceConfig(Service.IAS);

		assertEquals(0, iasConfig.size());
		assertThat(logCaptor.getWarnLogs()).contains("No service bindings for IAS service were found");
		assertDoesNotThrow(() -> cut.loadOauth2ServiceConfig(Service.IAS));
	}

	@Test
	void loadOAuth2ServiceConfig_noXsuaaServiceBinding(EnvironmentVariables environmentVariables) {
		environmentVariables.set(XSUAA_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/xsuaa-no-bindings");
		cut = new K8sServiceConfigurationResolver();

		assertDoesNotThrow(() -> cut.loadOauth2ServiceConfig(Service.XSUAA));
		assertThat(logCaptor.getWarnLogs()).contains("No service bindings for XSUAA service were found");
		assertEquals(0, cut.loadOauth2ServiceConfig(Service.XSUAA).size());
	}
}