package com.sap.cloud.security.token;

import javax.annotation.Nullable;

/**
 * Constants denoting the grant type of a Jwt access token as specified here:
 * https://tools.ietf.org/html/rfc6749
 */
public enum GrantType {
	CLIENT_CREDENTIALS("client_credentials"),
	/**
	 * @deprecated in favor of {@link #JWT_BEARER}.
	 */
	@Deprecated
	USER_TOKEN("user_token"),
	REFRESH_TOKEN("refresh_token"),
	PASSWORD("password"),
	JWT_BEARER("urn:ietf:params:oauth:grant-type:jwt-bearer"),
	SAML2_BEARER("urn:ietf:params:oauth:grant-type:saml2-bearer"),
	/**
	 * @deprecated SAP proprietary grant type.
	 */
	@Deprecated
	CLIENT_X509("client_x509"),
	AUTHORIZATION_CODE("authorization_code");

	private String claimName;

	GrantType(String claimName) {
		this.claimName = claimName;
	}

	@Override
	public String toString() {
		return claimName;
	}

	@Nullable
	public static GrantType from(String claimName) {
		for (GrantType grantType : values()) {
			if (grantType.claimName.equals(claimName)) {
				return grantType;
			}
		}
		return null;
	}

}
