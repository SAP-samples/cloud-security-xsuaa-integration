package com.sap.cloud.security.xsuaa.token;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoder;

public class SpringSecurityContext {

	private SpringSecurityContext() {
		// singleton, hide public constructor
	}

	/**
	 * Obtain the Token object from the Spring Security Context
	 * {@link SecurityContextHolder}
	 *
	 * @return Token object
	 * @throws AccessDeniedException
	 *             in case there is no token, user is not authenticated
	 *             <p>
	 *             Note: This method is introduced with xsuaa spring client lib.
	 */
	static public Token getToken() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null) {
			throw new AccessDeniedException("Access forbidden: not authenticated");
		}
		Object principal = authentication.getPrincipal();
		if (principal instanceof Token) {
			return (Token) principal;
		}
		throw new AccessDeniedException(
				"Access forbidden: SecurityContextHolder does not contain a principal of type 'Token' " + principal);
	}

	/**
	 * Initializes the Spring Security Context {@link SecurityContextHolder} and
	 * extracts the authorities. With version 1.5.0 you can configure your own
	 * {@link AuthoritiesExtractor} to specify how to extract the authorities.
	 *
	 * @param encodedJwtToken
	 *            the jwt token that is decoded with the given JwtDecoder
	 * @param xsuaaJwtDecoder
	 *            the decoder of type {@link XsuaaJwtDecoder}
	 * @param authoritiesExtractor
	 *            the extractor used to turn Jwt scopes into Spring Security
	 *            authorities.
	 */
	static public void init(String encodedJwtToken, JwtDecoder xsuaaJwtDecoder,
			AuthoritiesExtractor authoritiesExtractor) {
		Assert.isInstanceOf(XsuaaJwtDecoder.class, xsuaaJwtDecoder,
				"Passed JwtDecoder instance must be of type 'XsuaaJwtDecoder'");
		Jwt jwtToken = xsuaaJwtDecoder.decode(encodedJwtToken);

		TokenAuthenticationConverter authenticationConverter = new TokenAuthenticationConverter(authoritiesExtractor);
		Authentication authentication = authenticationConverter.convert(jwtToken);

		SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	/**
	 * Cleans up the Spring Security Context {@link SecurityContextHolder} and
	 * release thread locals for Garbage Collector to avoid memory leaks resources.
	 */
	static public void clear() {
		SecurityContextHolder.clearContext();
	}
}