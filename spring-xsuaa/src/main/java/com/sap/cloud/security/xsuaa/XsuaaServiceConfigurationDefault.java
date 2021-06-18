/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

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

	@Value("${xsuaa.identityzoneid:}")
	private String identityZoneId;

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
	public ClientIdentity getClientIdentity() {
		if (getCredentialType() == CredentialType.X509) {
			return new ClientCertificate(certificate, privateKey, getClientId());
		}
		return new ClientCredentials(getClientId(), getClientSecret());
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
}
