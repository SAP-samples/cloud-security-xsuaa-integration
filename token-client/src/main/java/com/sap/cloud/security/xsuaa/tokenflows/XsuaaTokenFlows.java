package com.sap.cloud.security.xsuaa.tokenflows;

import java.io.Serializable;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;

import static com.sap.cloud.security.xsuaa.ObjectsUtil.assertNotNull;

/**
 * A bean that can be {@code @Autowired} by applications to get access to token
 * flow builders. The token flow builders allow for the execution of a client
 * credentials flow (to get a technical user token) and a user token flow (to
 * get an exchange token with different scopes). <br>
 * 
 * This class uses a RestTemplate which it passes on to the builders.
 */
public class XsuaaTokenFlows implements Serializable {
	private static final long serialVersionUID = 2403173341950251507L;

	private final ClientCredentials clientCredentials;
	private final OAuth2TokenService oAuth2TokenService;
	private final OAuth2ServiceEndpointsProvider endpointsProvider;

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 * 
	 * @param oAuth2TokenService
	 *            the OAuth2TokenService that will be used to send the token
	 *            exchange request.
	 * @param endpointsProvider
	 *            the endpoint provider that serves the token endpoint.
	 * @param clientCredentials
	 *            the OAuth2.0 client id and secret
	 *
	 *            <pre>
	 * {@code
	 * String clientId     = "<<get your client id from your service binding>>";
	 * String clientSecret = "<<get your client secret from your service binding>>";
	 * String xsuaaBaseUrl = "<<get your xsuaa base url from service binding>>";
	 *
	 * OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaBaseUrl);
	 * ClientCredentials clientCredentials = new ClientCredentials(clientId, clientSecret);
	 * RestOperations restOperations = new RestTemplate();
	 *
	 * XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(restOperations, endpointsProvider, clientCredentials);
	 * }
	 *            </pre>
	 */
	public XsuaaTokenFlows(OAuth2TokenService oAuth2TokenService,
			OAuth2ServiceEndpointsProvider endpointsProvider, ClientCredentials clientCredentials) {
		assertNotNull(oAuth2TokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null");
		assertNotNull(clientCredentials, "ClientCredentials must not be null.");

		this.oAuth2TokenService = oAuth2TokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientCredentials = clientCredentials;
	}

	/**
	 * Creates a new User Token Flow builder object. The token passed needs to
	 * contain the scope {@code uaa.user}, otherwise an exception will be thrown
	 * when the flow is executed. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link UserTokenFlow} builder object.
	 */
	public UserTokenFlow userTokenFlow() {
		RefreshTokenFlow refreshTokenFlow = new RefreshTokenFlow(oAuth2TokenService, endpointsProvider,
				clientCredentials);

		return new UserTokenFlow(oAuth2TokenService, refreshTokenFlow, endpointsProvider, clientCredentials);
	}

	/**
	 * Creates a new Client Credentials Flow builder object. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public ClientCredentialsTokenFlow clientCredentialsTokenFlow() {
		return new ClientCredentialsTokenFlow(oAuth2TokenService, endpointsProvider, clientCredentials);
	}

	/**
	 * Creates a new Refresh Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public RefreshTokenFlow refreshTokenFlow() {
		return new RefreshTokenFlow(oAuth2TokenService, endpointsProvider, clientCredentials);
	}

}
