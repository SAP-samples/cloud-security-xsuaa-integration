package com.sap.cloud.security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a supported identity service.
 */
public enum Service {

	XSUAA("xsuaa"), IAS(getIasServiceName());

	private static String getIasServiceName() {
		Logger logger = LoggerFactory.getLogger(Service.class);
		if(System.getenv("IAS_SERVICE_NAME") != null) {
			logger.warn("As of version 2.8.0 IAS_SERVICE_NAME system environment variable is no longer needed. Service 'identity' is available with plan 'application'.");
		}
		return "identity";
	}

	private final String cloudFoundryName;

	Service(String cloudFoundryName) {
		this.cloudFoundryName = cloudFoundryName;
	}

	/**
	 * Returns the name of the identity service as it appears on Cloud Foundry
	 * marketplace.
	 * 
	 * @return name of the identity service in context of Cloud Foundry environment.
	 */
	public String getCFName() {
		return cloudFoundryName;
	}
}
