/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.config.k8s.K8sConstants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SystemStubsExtension.class)
class K8sEnvironmentTest {

	private static final String K8S_HOST_VALUE = "0.0.0.0";
	private static final WireMockServer WIREMOCK_SERVER = new WireMockServer(
			WireMockConfiguration.wireMockConfig().port(1111));
	private static Environment cut;

	@BeforeAll
	static void setup(EnvironmentVariables environmentVariables) throws IOException {
		environmentVariables.set(KUBERNETES_SERVICE_HOST, K8S_HOST_VALUE);

		String absolutePath = new File("src/test/resources").getAbsolutePath();

		environmentVariables.set(XSUAA_CONFIG_PATH, absolutePath + "/k8s/xsuaa");
		environmentVariables.set(IAS_CONFIG_PATH, absolutePath + "/k8s/ias");
		environmentVariables.set(SM_CONFIG_PATH, absolutePath + "/k8s/service-manager");

		String token = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		String serviceInstances = IOUtils.resourceToString("/k8s/serviceInstances.json", StandardCharsets.UTF_8);
		String servicePlans = IOUtils.resourceToString("/k8s/servicePlans.json", StandardCharsets.UTF_8);

		WIREMOCK_SERVER.stubFor(
				WireMock.post("/oauth/token").willReturn(WireMock.ok().withHeader("Content-Type", "application/json")
						.withBody("{\"access_token\": \"" + token + "\",  \"expires_in\": 1799}")));
		WIREMOCK_SERVER.stubFor(WireMock.get("/v1/service_plans")
				.willReturn(WireMock.ok().withHeader("Content-Type", "application/json").withBody(servicePlans)));
		WIREMOCK_SERVER.stubFor(WireMock.get("/v1/service_instances")
				.willReturn(WireMock.ok().withHeader("Content-Type", "application/json").withBody(serviceInstances)));
		WIREMOCK_SERVER.start();

		cut = K8sEnvironment.getInstance();
	}

	@AfterAll
	static void afterAll(EnvironmentVariables environmentVariables) throws Exception {
		environmentVariables.teardown();
	}

	@Test
	void getXsuaaConfiguration() {
		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertEquals("xsuaaClientId", config.getClientId());
	}

	@Test
	void getIasConfiguration() {
		OAuth2ServiceConfiguration config = cut.getIasConfiguration();
		assertEquals("iasClientId2", config.getClientId());
	}

	@Test
	void getNumberOfXsuaaConfigurations() {
		assertEquals(2, cut.getNumberOfXsuaaConfigurations());
	}

	@Test
	void getXsuaaConfigurationForTokenExchange() {
		OAuth2ServiceConfiguration config = cut.getXsuaaConfigurationForTokenExchange();
		assertEquals("xsuaaBrokerClientId", config.getClientId());
	}

	// TODO test case for missing SM config and negative test case with missing
	// xsuaa and ias configs
}