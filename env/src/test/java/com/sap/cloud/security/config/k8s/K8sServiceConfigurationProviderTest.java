/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.File;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.config.k8s.K8sConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(SystemStubsExtension.class)
class K8sServiceConfigurationProviderTest {

	private static final String ABSOLUTE_PATH = new File("src/test/resources").getAbsolutePath();
	private static K8sServiceConfigurationProvider cut;
	private static DefaultServiceManagerService smMock;

	@BeforeEach
	void beforeEach(EnvironmentVariables environmentVariables) {
		environmentVariables.set(XSUAA_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/xsuaa");
		environmentVariables.set(IAS_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/ias");
		environmentVariables.set(SM_CONFIG_PATH, ABSOLUTE_PATH + "/k8s/service-manager");
		Map<String, String> serviceInstancePlanMap = new HashMap<>();
		serviceInstancePlanMap.put("xsuaa-application", "application");
		serviceInstancePlanMap.put("xsuaa-broker", "broker");

		smMock = Mockito.mock(DefaultServiceManagerService.class);
		when(smMock.getServiceInstancePlans()).thenReturn(serviceInstancePlanMap);

		cut = new K8sServiceConfigurationProvider();
		cut.setServiceManagerClient(smMock);
	}

	@Test
	void getServiceConfigurations() {
		EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfig = cut
				.getServiceConfigurations();
		assertThat(serviceConfig).hasSize(2);
		assertThat(serviceConfig.get(Service.XSUAA)).hasSize(2);
		assertThat(serviceConfig.get(Service.IAS)).hasSize(2);
		assertThat(serviceConfig.get(Service.XSUAA).get(Plan.APPLICATION.toString())).isNotNull();
		assertThat(serviceConfig.get(Service.XSUAA).get(Plan.BROKER.toString())).isNotNull();
		assertThat(serviceConfig.get(Service.XSUAA).get(Plan.DEFAULT.toString())).isNull();
	}

	@Test
	void getServiceConfigurations_noXsuaaPlansAvailable() {
		when(smMock.getServiceInstancePlans()).thenReturn(Collections.emptyMap());
		EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfig = cut
				.getServiceConfigurations();

		assertThat(serviceConfig.get(Service.XSUAA)).isNotNull();
		assertThat(serviceConfig.get(Service.XSUAA)).hasSize(1);
		assertThat(serviceConfig.get(Service.XSUAA).get(Plan.APPLICATION.toString())).isNotNull();
	}

	@Test
	void getServiceConfigurations_noSmClient() {
		cut.setServiceManagerClient(null);
		EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfig = cut.getServiceConfigurations();

		assertThat(serviceConfig.get(Service.XSUAA)).isNotNull();
		assertThat(serviceConfig.get(Service.XSUAA)).hasSize(1);
		assertThat(serviceConfig.get(Service.XSUAA).get(Plan.APPLICATION.toString())).isNotNull();
	}

	@Test
	void getServiceConfigurations_noServiceBindingsAvailable(EnvironmentVariables environmentVariables) {
		environmentVariables.set(XSUAA_CONFIG_PATH, ABSOLUTE_PATH + "/no/binding");
		environmentVariables.set(IAS_CONFIG_PATH, ABSOLUTE_PATH + "/no/binding");
		environmentVariables.set(SM_CONFIG_PATH, ABSOLUTE_PATH + "/no/binding");

		cut = new K8sServiceConfigurationProvider();

		EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfig = cut.getServiceConfigurations();
		assertThat(serviceConfig).hasSize(2);
		assertThat(serviceConfig.get(Service.XSUAA)).isEmpty();
		assertThat(serviceConfig.get(Service.IAS)).isEmpty();
	}
}