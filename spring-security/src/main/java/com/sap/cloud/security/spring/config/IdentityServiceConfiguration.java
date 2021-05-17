/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.Service;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("sap.security.services.identity")
public class IdentityServiceConfiguration extends OAuth2ServiceConfigurationProperties {

	/**
	 * Creates a new instance to map configuration of a dedicated identity service.
	 *
	 */
	public IdentityServiceConfiguration() {
		super(Service.IAS);
	}
}
