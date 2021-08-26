/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.sap.cloud.security.config.k8s.K8sConstants.Plan;

/**
 * Loads the OAuth configuration ({@link OAuth2ServiceConfiguration}) of a
 * supported identity {@link Service} in the Kubernetes Environment by accessing
 * defaults service secrets paths "/etc/secrets/sapcp/xsuaa" for Xsuaa service
 * or "/etc/secrets/sapcp/ias" for IAS service.
 */
public class K8sEnvironment implements Environment {
	private static final Logger LOGGER = LoggerFactory.getLogger(K8sEnvironment.class);

	private static K8sEnvironment instance;
	private final Map<Service, Map<String, OAuth2ServiceConfiguration>> k8sServiceConfigurations;

	private K8sEnvironment() {
		k8sServiceConfigurations = new K8sServiceConfigurationProvider().getServiceConfigurations();
	}

	public static K8sEnvironment getInstance() {
		if (instance == null) {
			instance = new K8sEnvironment();
		}
		return instance;
	}

	@Nonnull
	@Override
	public Type getType() {
		return Type.KUBERNETES;
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfiguration() {
		Map<String, OAuth2ServiceConfiguration> xsuaaPlans = k8sServiceConfigurations.get(Service.XSUAA);

		return Optional.ofNullable(xsuaaPlans.get(Plan.APPLICATION.name()))
				.orElse(Optional.ofNullable(xsuaaPlans.get(Plan.BROKER.name()))
						.orElse(Optional.ofNullable(xsuaaPlans.get(Plan.SPACE.name()))
								.orElse(Optional.ofNullable(xsuaaPlans.get(Plan.DEFAULT.name()))
										.orElse(null))));

	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
		if (getNumberOfXsuaaConfigurations() > 1) {
			return k8sServiceConfigurations.get(Service.XSUAA).get(Plan.BROKER.name());
		}
		return getXsuaaConfiguration();
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getIasConfiguration() {
		Set<Map.Entry<String, OAuth2ServiceConfiguration>> iasConfigEntries = k8sServiceConfigurations
				.get(Service.IAS).entrySet();
		if (iasConfigEntries.size() > 1) {
			LOGGER.warn("{} IAS bindings found. Using the first one from the list", iasConfigEntries.size());
		}
		return iasConfigEntries.stream().findFirst().map(Map.Entry::getValue).orElse(null);
	}

	@Override
	public int getNumberOfXsuaaConfigurations() {
		return k8sServiceConfigurations.get(Service.XSUAA).size();
	}

}
