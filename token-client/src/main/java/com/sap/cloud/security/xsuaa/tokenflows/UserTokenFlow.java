package com.sap.cloud.security.xsuaa.tokenflows;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAuthorities;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.xsa.security.container.XSTokenRequest;

/**
 * A user token flow builder class. <br>
 * Applications retrieve an instance of this builder from
 * {@link XsuaaTokenFlows} and then create the flow request using a builder
 * pattern.
 */
public class UserTokenFlow {

	private XsuaaTokenFlowRequest request;
	private String token;
	private OAuth2TokenService tokenService;
	private boolean disableCache = false;
	private List<String> scopes = new ArrayList<>();

	/**
	 * Creates a new instance.
	 *
	 * @param tokenService
	 *            - the {@link OAuth2TokenService} used to execute the final
	 *            request.
	 * @param endpointsProvider
	 *            - the endpoints provider
	 * @param clientCredentials
	 *            - the OAuth client credentials
	 */
	UserTokenFlow(OAuth2TokenService tokenService, OAuth2ServiceEndpointsProvider endpointsProvider,
			ClientCredentials clientCredentials) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		assertNotNull(clientCredentials, "ClientCredentials must not be null.");

		this.tokenService = tokenService;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
		this.request.setClientId(clientCredentials.getId());
		this.request.setClientSecret(clientCredentials.getSecret());
	}

	/**
	 * Sets the JWT token that should be exchanged for another JWT token.
	 *
	 * @param token
	 *            - the JWT token.
	 * @return this builder object.
	 */
	public UserTokenFlow token(String token) {
		assertNotNull(token, "Token must not be null.");
		this.token = token;
		return this;
	}

	/**
	 * Adds additional authorization attributes to the request. <br>
	 * Clients can use this to request additional attributes in the
	 * {@code 'az_attr'} claim of the returned token.
	 *
	 * @param additionalAuthorizationAttributes
	 *            - the additional attributes.
	 * @return this builder.
	 */
	public UserTokenFlow attributes(Map<String, String> additionalAuthorizationAttributes) {
		this.request.setAdditionalAuthorizationAttributes(additionalAuthorizationAttributes);
		return this;
	}

	/**
	 * Sets the subdomain (tenant) the token is requested for.<br>
	 *
	 * @param subdomain
	 *            - the subdomain.
	 * @return this builder.
	 */
	public UserTokenFlow subdomain(String subdomain) {
		this.request.setSubdomain(subdomain);
		return this;
	}

	/**
	 * Sets the scope attribute for the token request. This will restrict the scope
	 * of the created token to the scopes provided. By default the scope is not
	 * restricted and the created token contains all granted scopes.
	 *
	 * If you specify a scope that is not authorized for the user, the token request
	 * will fail.
	 *
	 * @param scopes
	 *            - one or many scopes as string.
	 * @return this builder.
	 */
	public UserTokenFlow scopes(@Nonnull String... scopes) {
		Assertions.assertNotNull(scopes, "Scopes must not be null!");
		this.scopes = Arrays.asList(scopes);
		return this;
	}

	/**
	 * Can be used to disable the cache for the flow.
	 *
	 * @param disableCache
	 *            - disables cache when set to {@code true}.
	 * @return this builder.
	 */
	public UserTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	/**
	 * Executes this flow against the XSUAA endpoint. As a result the exchanged JWT
	 * token is returned. <br>
	 * Note, that in a standard flow, only the refresh token would be returned.
	 *
	 * @return the JWT instance returned by XSUAA.
	 * @throws IllegalStateException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws TokenFlowException
	 *             - in case of an error during the flow, or when the token cannot
	 *             be refreshed.
	 */
	public OAuth2TokenResponse execute() throws TokenFlowException {
		checkRequest(request);

		return requestUserToken(request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 *
	 * @param request
	 *            - the token flow request.
	 * @throws IllegalArgumentException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws IllegalStateException
	 *             - in case the user token has not been set
	 */
	private void checkRequest(XSTokenRequest request) throws IllegalArgumentException {
		if (token == null) {
			throw new IllegalStateException(
					"User token not set. Make sure to have called the token() method on UserTokenFlow builder.");
		}

		if (!request.isValid()) {
			throw new IllegalArgumentException(
					"User token flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Sends the user token flow request to XSUAA.
	 *
	 * @param request
	 *            - the token flow request.
	 * @return the exchanged JWT from XSUAA.
	 * @throws TokenFlowException
	 *             in case of an error during the flow.
	 */
	private OAuth2TokenResponse requestUserToken(XsuaaTokenFlowRequest request) throws TokenFlowException {
		Map<String, String> optionalParameter = new HashMap<>();
		String authorities = buildAuthorities(request);

		if (authorities != null) {
			optionalParameter.put(AUTHORITIES, authorities); // places JSON inside the URI !?!
		}

		String scopesParameter = scopes.stream().collect(Collectors.joining(", "));
		if (!scopesParameter.isEmpty()) {
			optionalParameter.put(SCOPE, scopesParameter);
		}

		try {
			return tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
					request.getTokenEndpoint(),
					new ClientCredentials(request.getClientId(), request.getClientSecret()),
					token, request.getSubdomain(), optionalParameter, disableCache);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format(
							"Error requesting token with grant_type 'urn:ietf:params:oauth:grant-type:jwt-bearer': %s",
							e.getMessage()),
					e);
		}
	}

	@Nullable
	private String readFromPropertyFile(String property) {
		String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		String appConfigPath = rootPath + "application.properties";

		Properties appProps = new Properties();
		try {
			appProps.load(new FileInputStream(appConfigPath));
			return appProps.getProperty(property);
		} catch (IOException e) {
			return null;
		}
	}

}
