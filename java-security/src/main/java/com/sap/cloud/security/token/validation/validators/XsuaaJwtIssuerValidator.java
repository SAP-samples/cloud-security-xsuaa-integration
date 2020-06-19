package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.*;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

/**
 * Validates that the jwt access token is issued by a trust worthy identity
 * service. In case of XSUAA does the token key url (jku JWT header parameter)
 * must match the identity service domain.
 */
class XsuaaJwtIssuerValidator implements Validator<Token> {
	private final String domain;
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	/**
	 *
	 * @param uaaDomain
	 *            the domain of the identity service
	 *            {@link OAuth2ServiceConfiguration#getProperty(String)}
	 */
	XsuaaJwtIssuerValidator(String uaaDomain) {
		assertHasText(uaaDomain, "XsuaaJwtIssuerValidator requires uaaDomain.");
		this.domain = uaaDomain;
	}

	@Override
	public ValidationResult validate(Token token) {
		String tokenKeyUrl = token.getHeaderParameterAsString(TokenHeader.JWKS_URL);
		URI jkuUri;

		if (tokenKeyUrl == null || tokenKeyUrl.trim().isEmpty()) {
			return createInvalid(
					"Issuer validation can not be performed because Jwt token does not contain 'jku' header parameter.");
		}
		try {
			jkuUri = URI.create(tokenKeyUrl);
		} catch (IllegalArgumentException e) {
			return createInvalid(
					"Issuer validation can not be performed because Jwt token does not contain a valid uri as 'jku' header parameter.");
		}
		if (!matchesTokenKeyUrlDomain(jkuUri)) {
			return createInvalid(
					"Issuer is not trusted because 'jku' '{}' does not match uaa domain '{}' of the identity service.",
					jkuUri, domain);
		}
		if (!matchesTokenKeyEndpoint(jkuUri)) {
			return createInvalid(
					"Jwt token does not contain a valid 'jku' header parameter.",
					jkuUri, domain);
		}
		return createValid();
	}

	private boolean matchesTokenKeyUrlDomain(URI jkuUri) {
		return jkuUri.getHost() != null && jkuUri.getHost().endsWith(domain);
	}

	private boolean matchesTokenKeyEndpoint(URI jkuUri) {
		return jkuUri.getPath().endsWith("token_keys") && jkuUri.getQuery() == null && jkuUri.getFragment() == null;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		XsuaaJwtIssuerValidator that = (XsuaaJwtIssuerValidator) o;

		return domain.equals(that.domain);
	}

	@Override
	public int hashCode() {
		return domain.hashCode();
	}
}
