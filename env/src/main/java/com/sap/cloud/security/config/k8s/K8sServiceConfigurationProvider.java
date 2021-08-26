/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

/**
 * The K8sServiceConfigurationProvider provides the information of all bound
 * service configurations.
 */
class K8sServiceConfigurationProvider {
	private static final Logger LOGGER = LoggerFactory.getLogger(K8sServiceConfigurationProvider.class);

	private DefaultServiceManagerService serviceManagerClient;
	private final K8sServiceConfigurationResolver serviceConfigurationResolver;

	K8sServiceConfigurationProvider() {
		this.serviceConfigurationResolver = new K8sServiceConfigurationResolver();
		if (serviceConfigurationResolver.loadServiceManagerConfig() != null) {
			this.serviceManagerClient = new DefaultServiceManagerService(
					serviceConfigurationResolver.loadServiceManagerConfig());
		}
	}

	void setServiceManagerClient(DefaultServiceManagerService serviceManagerClient) {
		this.serviceManagerClient = serviceManagerClient;
	}

	/**
	 * Gets all service configurations from the mounted file volumes.
	 *
	 * @return the service configurations map of IAS and XSUAA services with their
	 *         corresponding OAuth2ServiceConfigurations. For Xsuaa Map key is the
	 *         service plan name, for IAS key is the service instance name.
	 */
	EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> getServiceConfigurations() {
		EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfigurations = new EnumMap<>(Service.class);

		serviceConfigurations.put(Service.XSUAA, mapXsuaaServicePlans(serviceConfigurationResolver
				.loadOauth2ServiceConfig(Service.XSUAA)));
		serviceConfigurations.put(Service.IAS, serviceConfigurationResolver
				.loadOauth2ServiceConfig(Service.IAS));

		return serviceConfigurations;
	}

	private Map<String, OAuth2ServiceConfiguration> mapXsuaaServicePlans(
			Map<String, OAuth2ServiceConfiguration> allXsuaaServices) {
		Map<String, OAuth2ServiceConfiguration> allXsuaaServicesWithPlans = new HashMap<>();// <planName, config>

		if (!allXsuaaServices.isEmpty()) {
			if (serviceManagerClient == null) {
				Map.Entry<String, OAuth2ServiceConfiguration> entrySet = allXsuaaServices.entrySet().iterator().next();
				LOGGER.warn(
						"No service-manager client available, taking first Xsuaa service ({}) and setting the plan to APPLICATION",
						entrySet.getKey());
				return Collections.singletonMap("APPLICATION", entrySet.getValue());
			}
			Map<String, String> serviceInstancePlans = serviceManagerClient.getServiceInstancePlans();// <xsuaaName,planName>
			if (serviceInstancePlans.isEmpty()) {
				Map.Entry<String, OAuth2ServiceConfiguration> entrySet = allXsuaaServices.entrySet().iterator().next();
				LOGGER.warn(
						"No plans were fetched from service manager, taking first Xsuaa service ({}) and setting the plan to APPLICATION",
						entrySet.getKey());
				return Collections.singletonMap("APPLICATION", entrySet.getValue());
			}
			allXsuaaServices.keySet().forEach(
					k -> allXsuaaServicesWithPlans.put(serviceInstancePlans.get(k).toUpperCase(), allXsuaaServices.get(k)));
		}
		return allXsuaaServicesWithPlans;
	}
}
