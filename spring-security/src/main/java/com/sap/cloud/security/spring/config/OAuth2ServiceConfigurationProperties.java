package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;

import java.net.URI;
import java.util.Map;

/**
 * PoJo of Spring configuration properties. It implements the
 * {@link OAuth2ServiceConfiguration} and enhances it with
 * <ul>
 * <li>setters</li>
 * <li>Xsuaa specific setters to map Xsuaa specific configuration such as
 * {@code uaadomain}, {@code xsappname}</li>
 * </ul>
 * You can define your own prefix when declaring
 * {@code @ConfigurationProperties("xsuaa")}. This then needs to be mapped to
 * {@code $vcap.services.<your service instance name>.credentials} as part of
 * your application properties. <br>
 *
 * Alternatively, its possible to directly map the properties to
 * {@code VCAP_SERVICES} system environment variable: <br>
 * {@code @ConfigurationProperties("vcap.services.<your service instance name>.credentials")}
 */
public class OAuth2ServiceConfigurationProperties implements OAuth2ServiceConfiguration {
	OAuth2ServiceConfigurationBuilder builder;
	OAuth2ServiceConfiguration configuration;

	/**
	 * Creates a new instance to map configuration of a dedicated identity service.
	 * 
	 * @param service
	 *            the kind of service
	 */
	public OAuth2ServiceConfigurationProperties(Service service) {
		builder = OAuth2ServiceConfigurationBuilder.forService(service);
	}

	@Override
	public String getClientId() {
		return getConfiguration().getClientId();
	}

	/**
	 * Sets client id of identity service instance.
	 * 
	 * @param clientId
	 *            client identifier
	 */
	public void setClientId(String clientId) {
		builder.withClientId(clientId);
	}

	@Override
	public String getClientSecret() {
		return getConfiguration().getClientSecret();
	}

	/**
	 * Sets client secret of identity service instance.
	 * 
	 * @param clientSecret
	 *            client secret
	 */
	public void setClientSecret(String clientSecret) {
		builder.withClientSecret(clientSecret);
	}

	@Override
	public URI getUrl() {
		return getConfiguration().getUrl();
	}

	// TODO https://github.com/SAP/cloud-security-xsuaa-integration/pull/457
	/**
	 * public String getDomain() { return getConfiguration().getDomain(); }
	 * 
	 * public void setDomain(String domain) { if(Service.XSUAA.equals(getService()))
	 * { builder.withProperty(CFConstants.XSUAA.UAA_DOMAIN, domain); } else {
	 * builder.withProperty(CFConstants.IAS.DOMAIN, domain); } }
	 **/

	/**
	 * Sets base URL of the OAuth2 identity service instance. In multi tenancy
	 * scenarios this is the url where the service instance was created.
	 * 
	 * @param url
	 *            base url
	 */
	public void setUrl(String url) {
		builder.withUrl(url);
	}

	/**
	 * Sets uaa domain of identity service instance.
	 *
	 * @param uaaDomain
	 *            uaa domain
	 */
	public void setUaaDomain(String uaaDomain) {
		builder.withProperty(CFConstants.XSUAA.UAA_DOMAIN, uaaDomain);
	}

	/**
	 * Sets application name of xsuaa service instance.
	 *
	 * @param xsAppName
	 *            the xsappname as specified in the {@code xs-security.json}.
	 */
	public void setXsAppName(String xsAppName) {
		builder.withProperty(CFConstants.XSUAA.APP_ID, xsAppName);
	}

	/**
	 * Sets the verification key of xsuaa service instance.
	 *
	 * @param verificationKey
	 *            the verification key that provides the public key of the private
	 *            key the token is signed with.
	 */
	public void setVerificationKey(String verificationKey) {
		builder.withProperty(CFConstants.XSUAA.VERIFICATION_KEY, verificationKey);
	}

	@Override
	public String getProperty(String name) {
		return getConfiguration().getProperty(name);
	}

	@Override
	public Map<String, String> getProperties() {
		return getConfiguration().getProperties();
	}

	@Override
	public boolean hasProperty(String name) {
		return getConfiguration().hasProperty(name);
	}

	@Override
	public Service getService() {
		return getConfiguration().getService();
	}

	@Override
	public boolean isLegacyMode() {
		return getConfiguration().isLegacyMode();
	}

	protected OAuth2ServiceConfiguration getConfiguration() {
		if (configuration == null) {
			configuration = builder.build();
		}
		return configuration;
	}
}
