package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;

import javax.annotation.Nullable;
import java.security.Principal;
import java.util.Collection;

/**
 * Class that represents the result of the authentication check performed by a
 * {@link TokenAuthenticator}.
 */
public interface TokenAuthenticationResult {
	/**
	 * The token that was checked for authentication.
	 *
	 * @return the token.
	 */
	@Nullable
	Token getToken();

	/**
	 * The principal associated with the request.
	 *
	 * @return the principal.
	 */
	@Nullable
	Principal getPrincipal();

	/**
	 * The authentication scopes. Can be empty.
	 *
	 * @return the scopes as a list of strings.
	 */
	Collection<String> getScopes();

	/**
	 * @return true if authenticated.
	 */
	boolean isAuthenticated();

	/**
	 * If not authenticated, this returns the reason why as text.
	 *
	 * @return the textual description why the request was not authenticated. Empty
	 *         string if authenticated.
	 */
	String getUnauthenticatedReason();
}
