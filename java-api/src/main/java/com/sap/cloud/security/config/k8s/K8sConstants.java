/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.cf.CFConstants;

/**
 * Constants that simplifies access to service configuration properties in the
 * Kubernetes environment.
 */
public class K8sConstants {
	public static final String KUBERNETES_SERVICE_HOST = "KUBERNETES_SERVICE_HOST";
	static final String XSUAA_CONFIG_PATH_DEFAULT = "/etc/secrets/sapcp/xsuaa";
	static final String IAS_CONFIG_PATH_DEFAULT = "/etc/secrets/sapcp/ias";
	static final String SERVICE_MANAGER_CONFIG_PATH_DEFAULT = "/etc/secrets/sapcp/service-manager";

	/**
	 * System variable name for user defined Xsuaa configuration path
	 */
	static final String XSUAA_CONFIG_PATH = "XSUAA_CONFIG_PATH";
	/**
	 * System variable name for user defined IAS configuration path
	 */
	static final String IAS_CONFIG_PATH = "IAS_CONFIG_PATH";
	/**
	 * System variable name for user defined Service manager configuration path
	 */
	static final String SM_CONFIG_PATH = "SM_CONFIG_PATH";

	private K8sConstants() {
	}

	/**
	 * Represents the service plans available in Kyma Service Catalog. The various
	 * plans are considered in {@code K8sEnvironment}
	 */
	public enum Plan {
		DEFAULT, BROKER, APPLICATION, SPACE, APIACCESS, SYSTEM;

		public static CFConstants.Plan from(String planAsString) {
			return CFConstants.Plan.valueOf(planAsString.toUpperCase());
		}

	}
}
