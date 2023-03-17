package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.*;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.SCOPE;

/**
 * A JWT bearer token flow builder. <br>
 * Applications can use this flow to exchange a given user token for a new JWT token.
 */
public class JwtBearerTokenFlow {

    private final OAuth2TokenService tokenService;
    private final OAuth2ServiceEndpointsProvider endpointsProvider;
    private final ClientIdentity clientIdentity;
    private String bearerToken;
    private List<String> scopes = new ArrayList<>();
    private String subdomain;
    private Map<String, String> optionalParameters;
    private boolean disableCache;

    public JwtBearerTokenFlow(@Nonnull OAuth2TokenService tokenService,
                              @Nonnull OAuth2ServiceEndpointsProvider endpointsProvider,
                              @Nonnull ClientIdentity clientIdentity) {
        Assertions.assertNotNull(tokenService, "OAuth2TokenService must not be null!");
        Assertions.assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null!");
        Assertions.assertNotNull(clientIdentity, "ClientIdentity must not be null!");

        this.tokenService = tokenService;
        this.endpointsProvider = endpointsProvider;
        this.clientIdentity = clientIdentity;
    }

    /**
     * Sets the bearer token for the next execution.
     *
     * @param bearerToken
     *            - the bearer token.
     * @return this builder.
     */
    public JwtBearerTokenFlow bearerToken(String bearerToken) {
        this.bearerToken = bearerToken;
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
    public JwtBearerTokenFlow scopes(@Nonnull String... scopes) {
        Assertions.assertNotNull(scopes, "Scopes must not be null!");
        this.scopes = Arrays.asList(scopes);
        return this;
    }

    /**
     * Set the Subdomain the token is requested for.
     *
     * @param subdomain
     *            - the subdomain.
     * @return this builder.
     */
    public JwtBearerTokenFlow subdomain(String subdomain) {
        this.subdomain = subdomain;
        return this;
    }

    /**
     * Adds additional authorization attributes to the request.
     *
     * @param optionalParameters
     *            - the optional parameters.
     * @return this builder.
     */
    public JwtBearerTokenFlow optionalParameters(Map<String, String> optionalParameters) {
        this.optionalParameters = optionalParameters;
        return this;
    }

    /**
     * Can be used to disable the cache for the flow.
     *
     * @param disableCache
     *            - disables cache when set to {@code true}.
     * @return this builder.
     */
    public JwtBearerTokenFlow disableCache(boolean disableCache) {
        this.disableCache = disableCache;
        return this;
    }

    /**
     * Executes this flow against the XSUAA endpoint. As a result the exchanged JWT
     * token is returned.
     *
     * @return the JWT instance returned by XSUAA.
     * @throws IllegalStateException
     *             - in case not all mandatory fields of the token flow request have
     *             been set.
     * @throws TokenFlowException
     *             - in case of an error during the flow, or when the token cannot
     *             be obtained.
     */
    public OAuth2TokenResponse execute() throws TokenFlowException {
        if (bearerToken == null) {
            throw new IllegalStateException("A bearerToken must be set before executing the flow.");
        }

        String scopesParameter = String.join(" ", scopes);
        if (!scopesParameter.isEmpty()) {
            if(optionalParameters == null) {
                optionalParameters(Map.of(SCOPE, scopesParameter));
            } else {
                optionalParameters.put(SCOPE, scopesParameter);
            }
        }

        try {
            return tokenService
                    .retrieveAccessTokenViaJwtBearerTokenGrant(endpointsProvider.getTokenEndpoint(), clientIdentity,
                            bearerToken, subdomain, optionalParameters, disableCache);
        } catch (OAuth2ServiceException e) {
            throw new TokenFlowException(
                    String.format("Error requesting user token with grant_type '%s': %s",
                            OAuth2TokenServiceConstants.GRANT_TYPE_JWT_BEARER, e.getMessage()), e);
        }
    }
}
