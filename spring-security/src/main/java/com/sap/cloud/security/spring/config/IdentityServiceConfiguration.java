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
