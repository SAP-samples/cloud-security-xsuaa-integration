package com.sap.cloud.security.xsuaa.autoconfiguration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestOperations;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a class of type {@link XsuaaTokenFlows} on the
 * classpath.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaTokenFlowAutoConfiguration.class})
 * or with property spring.xsuaa.flows.auto = false
 */
@Configuration
@ConditionalOnClass(XsuaaTokenFlows.class)
@ConditionalOnProperty(prefix = "spring.xsuaa.flows", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaTokenFlowAutoConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(XsuaaTokenFlowAutoConfiguration.class);

	/**
	 * Creates a new {@link XsuaaTokenFlows} bean that applications can auto-wire
	 * into their controllers to perform a programmatic token flow exchange.
	 *
	 * @param xsuaaRestOperations
	 *            - the {@link RestOperations} to use for the token flow exchange.
	 * @param xsuaaServiceConfiguration
	 *            - the {@link XsuaaServiceConfiguration} to configure the Xsuaa
	 *            Base Url.
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
	@ConditionalOnBean({ XsuaaServiceConfiguration.class, RestOperations.class })
	@ConditionalOnMissingBean
	public XsuaaTokenFlows xsuaaTokenFlows(RestOperations xsuaaRestOperations,
			XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		logger.debug("auto-configures XsuaaTokenFlows using restOperations of type: {}", xsuaaRestOperations);
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				xsuaaServiceConfiguration.getUaaUrl());
		ClientCredentials clientCredentials = new ClientCredentials(xsuaaServiceConfiguration.getClientId(),
				xsuaaServiceConfiguration.getClientSecret());
		OAuth2TokenService oAuth2TokenService = new XsuaaOAuth2TokenService(xsuaaRestOperations);
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientCredentials);
	}
}
