package com.sap.cloud.security.xsuaa.client;

public class OAuth2TokenServiceConstants {

	private OAuth2TokenServiceConstants() {
		throw new IllegalStateException("Utility class");
	}

	public static final String ACCESS_TOKEN = "access_token";
	public static final String EXPIRES_IN = "expires_in";
	public static final String REFRESH_TOKEN = "refresh_token";
	public static final String CLIENT_ID = "client_id";
	public static final String CLIENT_SECRET = "client_secret";

	public static final String GRANT_TYPE = "grant_type";
	public static final String GRANT_TYPE_USER_TOKEN = "user_token";
	public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
	public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
	public static final String TOKEN_TYPE_OPAQUE = "opaque";

	public static final String PARAMETER_CLIENT_ID = "client_id";
}
