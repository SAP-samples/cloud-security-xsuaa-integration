/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

/**
 * Default Implementation
 *
 */
public class DefaultAuthenticationInformationExtractor implements AuthenticationInformationExtractor {

	private static final String SUBDOMAIN_HEADER = "X-Identity-Zone-Subdomain";

	private final String subDomain;
	private List<AuthenticationMethod> authenticationMethods = Arrays.asList(AuthenticationMethod.BASIC,
			AuthenticationMethod.OAUTH2);

	public DefaultAuthenticationInformationExtractor() {
		super();
		this.subDomain = null;
	}

	public DefaultAuthenticationInformationExtractor(String subDomain) {
		super();
		this.subDomain = subDomain;
	}

	public DefaultAuthenticationInformationExtractor(AuthenticationMethod... authenticationMethods) {
		this(null, authenticationMethods);
	}

	public DefaultAuthenticationInformationExtractor(String subDomain, AuthenticationMethod... authenticationMethods) {
		super();
		this.subDomain = subDomain;
		this.authenticationMethods = Arrays.asList(authenticationMethods);
	}

	@Override
	public Optional<String> getSubdomain() {
		if (subDomain != null && !subDomain.trim().isEmpty()) {
			return Optional.of(subDomain);
		}
		return Optional.empty();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.sap.cloud.security.xsuaa.extractor.AuthenticationInformation#
	 * getSubdomain(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public Optional<String> getSubdomain(HttpServletRequest request) {
		Optional<String> subdomainResult = getSubdomain();
		if (subdomainResult.isPresent()) {
			return subdomainResult;
		}

		Objects.requireNonNull(request, "Request must not be null");

		String subdomainParam = request.getParameter(SUBDOMAIN_HEADER);
		String subdomainHeader = request.getHeader(SUBDOMAIN_HEADER);

		if (!Objects.isNull(subdomainParam)) {
			return Optional.of(subdomainParam);
		}
		if (!Objects.isNull(subdomainHeader)) {
			return Optional.of(subdomainHeader);
		}
		return Optional.empty();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.sap.cloud.security.xsuaa.extractor.AuthenticationInformation#
	 * getAuthenticationMethods(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
		return authenticationMethods;
	}

}
