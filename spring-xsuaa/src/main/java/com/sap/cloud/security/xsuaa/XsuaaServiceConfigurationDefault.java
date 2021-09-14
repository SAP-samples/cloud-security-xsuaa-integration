/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.util.Map;
import java.util.Properties;

@Configuration
public class XsuaaServiceConfigurationDefault implements XsuaaServiceConfiguration {

	@Value("${xsuaa.clientid:}")
	private String clientId;

	@Value("${xsuaa.clientsecret:}")
	private String clientSecret;

	@Value("${xsuaa.url:}")
	private String uaaUrl;

	@Value("${xsuaa.uaadomain:#{null}}")
	private String uaadomain;

	@Value("${xsuaa.xsappname:}")
	private String appid;

	@Value("${xsuaa.key:}")
	private String privateKey;

	@Value("${xsuaa.certificate:}")
	private String certificate;

	@Value("${xsuaa.verificationkey:}")
	private String verificationKey;

	@Value("${xsuaa.credentialtype:#{null}}")
	private String credentialType;

	@Value("${xsuaa.certurl:#{null}}")
	private String certUrl;

	private Properties vcapServiceProperties;

	/*
	 * (non-Javadoc)
	 *
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getClientId()
	 */
	@Override
	public String getClientId() {
		return clientId;
	}

	@Override
	public String getClientSecret() {
		return clientSecret;
	}

	@Override
	public String getUaaUrl() {
		return uaaUrl;
	}

	@Override
	public String getAppId() {
		return this.appid;
	}

	@Override
	public String getUaaDomain() {
		return uaadomain;
	}

	@Override
	public String getVerificationKey() {
		return verificationKey;
	}

	@Override
	public CredentialType getCredentialType() {
		return CredentialType.from(credentialType);
	}

	@Override
	public URI getCertUrl() {
		return URI.create(certUrl);
	}

	private Properties getVcapServiceProperties() {
		if (vcapServiceProperties == null) {
			vcapServiceProperties = new Properties();
			if (Environments.getCurrent().getNumberOfXsuaaConfigurations() > 1) {
				throw new IllegalStateException(
						"Found more than one xsuaa bindings. Make use of Environments.getCurrent() directly.");
			}
			OAuth2ServiceConfiguration xsuaaConfiguration = Environments.getCurrent().getXsuaaConfiguration();
			if(xsuaaConfiguration != null) {
				for (Map.Entry<String, String> property : xsuaaConfiguration.getProperties()
						.entrySet()) {
					vcapServiceProperties.put(property.getKey(), property.getValue());
				}
			}
		}
		return vcapServiceProperties;
	}

	@Override
	public String getProperty(String name) {
		return getVcapServiceProperties().getProperty(name);
	}

	@Override
	public boolean hasProperty(String name) {
		return getVcapServiceProperties().containsKey(name);
	}
}
