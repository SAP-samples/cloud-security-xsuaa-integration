package com.sap.cloud.security.xsuaa.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;

import reactor.core.publisher.Mono;

public class ReactiveSecurityContext {
	private static Logger logger = LoggerFactory.getLogger(ReactiveSecurityContext.class);

	private ReactiveSecurityContext() {
	}

	/**
	 * Obtain the Token object from the Spring Reactive SecurityContext
	 *
	 * @return Mono object of type token or error of class
	 *         {@link AccessDeniedException} in case there is no token, user is not
	 *         authenticated.
	 */
	static public Mono<XsuaaToken> getToken() {
		return ReactiveSecurityContextHolder.getContext()
				.switchIfEmpty(Mono.error(new AccessDeniedException("Access forbidden: not authenticated")))
				.map(SecurityContext::getAuthentication)
				.map(Authentication::getCredentials)
				.map(credentials -> new XsuaaToken((Jwt) credentials))
				.doOnSuccess(token -> logger.info("Got Jwt token: {}", token))
				.doOnError(throwable -> logger.error("ERROR to getToken", throwable));
	}
}
