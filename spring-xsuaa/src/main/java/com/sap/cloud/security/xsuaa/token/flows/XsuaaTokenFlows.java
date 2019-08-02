/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;

import com.sap.cloud.security.xsuaa.backend.OAuth2ServerEndpointsProvider;
import com.sap.cloud.security.xsuaa.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.backend.OAuth2Server;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

/**
 * A bean that can be {@code @Autowired} by applications to get access to token
 * flow builders. The token flow builders allow for the execution of a client
 * credentials flow (to get a technical user token) and a user token flow (to
 * get an exchange token with different scopes). <br>
 * 
 * This class uses a RestTemplate which it passes on to the builders.
 */
public class XsuaaTokenFlows {

	private RestTemplate restTemplate;
	private VariableKeySetUriTokenDecoder tokenDecoder;

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 * 
	 * @param restTemplate
	 *            the RestTemplate instance that will be used to send the token
	 *            exchange request.
	 * @param tokenDecoder
	 *            the {@link VariableKeySetUriTokenDecoder} instance used internally
	 *            to decode a Jwt token.
	 */
	public XsuaaTokenFlows(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder) {
		Assert.notNull(restTemplate, "RestTemplate must not be null.");
		Assert.notNull(tokenDecoder, "TokenDecoder must not be null.");

		this.restTemplate = restTemplate;
		this.tokenDecoder = tokenDecoder;
	}

	/**
	 * Creates a new User Token Flow builder object. The token passed needs to
	 * contain the scope {@code uaa.user}, otherwise an exception will be thrown
	 * when the flow is executed. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @param xsuaaBaseUri
	 *            - the base URI of XSUAA that the flow will be executed against.
	 * @return the {@link UserTokenFlow} builder object.
	 */
	public UserTokenFlow userTokenFlow(URI xsuaaBaseUri) {
		Assert.notNull(xsuaaBaseUri, "XSUAA base URI must not be null.");

		OAuth2Server oAuth2Server = createOAuth2Server(xsuaaBaseUri);
		RefreshTokenFlow refreshTokenFlow = new RefreshTokenFlow(oAuth2Server, tokenDecoder);

		return new UserTokenFlow(oAuth2Server, refreshTokenFlow);
	}

	/**
	 * Creates a new Client Credentials Flow builder object. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @param xsuaaBaseUri
	 *            - the base URI of XSUAA that the flow will be executed against.
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public ClientCredentialsTokenFlow clientCredentialsTokenFlow(URI xsuaaBaseUri) {
		Assert.notNull(xsuaaBaseUri, "XSUAA base URI must not be null.");

		return new ClientCredentialsTokenFlow(createOAuth2Server(xsuaaBaseUri), tokenDecoder);
	}

	/**
	 * Creates a new Refresh Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @param xsuaaBaseUri
	 *            - the base URI of XSUAA that the flow will be executed against.
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public RefreshTokenFlow refreshTokenFlow(URI xsuaaBaseUri) {
		Assert.notNull(xsuaaBaseUri, "XSUAA base URI must not be null.");

		return new RefreshTokenFlow(createOAuth2Server(xsuaaBaseUri), tokenDecoder);
	}

	OAuth2Server createOAuth2Server(URI xsuaaBaseUri) {
		OAuth2ServerEndpointsProvider oAuth2ServerEndpointsProvider = new XsuaaDefaultEndpoints(xsuaaBaseUri);
		return new OAuth2Server(restTemplate, oAuth2ServerEndpointsProvider);
	}
}
